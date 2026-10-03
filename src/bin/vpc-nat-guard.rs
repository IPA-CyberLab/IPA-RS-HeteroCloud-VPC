//! Node-local fail-closed guard. Tenant workloads never receive host privileges.
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    routing::get,
};
use heterocloud_vpc::*;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client, ResourceExt,
    api::{DynamicObject, ListParams, Patch, PatchParams},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::RwLock};
#[derive(Default)]
struct Snapshot {
    ready: BTreeMap<String, IpAddr>,
    at: Option<Instant>,
}
type Shared = Arc<RwLock<Snapshot>>;
#[derive(Deserialize)]
struct Probe {
    pod_uid: String,
}
async fn ready(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<Probe>,
) -> StatusCode {
    let state = s.read().await;
    if state
        .at
        .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        && state.ready.get(&q.pod_uid) == Some(&peer.ip())
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn health(State(s): State<Shared>) -> StatusCode {
    if s.read()
        .await
        .at
        .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn command(bin: &str, args: &[&str]) -> Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(bin).args(args).kill_on_drop(true).output(),
    )
    .await??;
    ensure!(
        result.status.success(),
        "{} failed: {}",
        bin,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
async fn set(name: &str, kind: &str, entries: &BTreeSet<String>) -> Result<()> {
    let temp = format!("{name}-next");
    for set_name in [name, temp.as_str()] {
        let mut args = vec![
            "create", set_name, kind, "family", "inet", "maxelem", "131072", "-exist",
        ];
        if name == "HC-VPC-LOCAL" {
            args.extend(["timeout", "10"]);
        }
        command("ipset", &args).await?;
    }
    command("ipset", &["flush", &temp]).await?;
    // ipset restore batches large fleets instead of spawning a process per Pod.
    let body = entries
        .iter()
        .map(|ip| format!("add {temp} {ip}\n"))
        .collect::<String>();
    use tokio::io::AsyncWriteExt;
    let mut child = Command::new("ipset")
        .arg("restore")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .context("ipset stdin")?
        .write_all(body.as_bytes())
        .await?;
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    ensure!(output.status.success(), "ipset restore failed");
    command("ipset", &["swap", &temp, name]).await?;
    Ok(())
}
async fn install(bin: &str, protected: &BTreeSet<String>) -> Result<()> {
    // Preserve existing managed IPs across guard restarts; clearing them would briefly bypass the guard.
    command(
        "ipset",
        &[
            "create",
            "HC-VPC-MANAGED",
            "hash:ip",
            "family",
            "inet",
            "maxelem",
            "131072",
            "-exist",
        ],
    )
    .await?;
    set("HC-VPC-LOCAL", "hash:ip", &BTreeSet::new()).await?;
    set("HC-VPC-PRIVATE", "hash:net", protected).await?;
    // Atomic restore replaces only our chain. Existing node, kube-router and
    // EgressGateway chains and policies are preserved.
    let restore = format!("{bin}-restore");
    let input = "*mangle\n:HC-VPC-GUARD - [0:0]\n-F HC-VPC-GUARD\n-A HC-VPC-GUARD -m set ! --match-set HC-VPC-MANAGED src -j RETURN\n-A HC-VPC-GUARD -m set --match-set HC-VPC-PRIVATE dst -j RETURN\n-A HC-VPC-GUARD -m conntrack --ctdir REPLY -j RETURN\n-A HC-VPC-GUARD -o egress.vxlan -j RETURN\n-A HC-VPC-GUARD -m set --match-set HC-VPC-LOCAL src -j RETURN\n-A HC-VPC-GUARD -j DROP\nCOMMIT\n";
    use tokio::io::AsyncWriteExt;
    let mut child = Command::new(&restore)
        .args(["--noflush", "--wait", "5"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .context("iptables stdin")?
        .write_all(input.as_bytes())
        .await?;
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "iptables restore: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exists = Command::new(bin)
        .args([
            "-w",
            "5",
            "-t",
            "mangle",
            "-C",
            "FORWARD",
            "-j",
            "HC-VPC-GUARD",
        ])
        .output()
        .await?;
    if !exists.status.success() {
        command(
            bin,
            &[
                "-w",
                "5",
                "-t",
                "mangle",
                "-I",
                "FORWARD",
                "1",
                "-j",
                "HC-VPC-GUARD",
            ],
        )
        .await?;
    }
    Ok(())
}
struct Guard {
    pods: Api<Pod>,
    vpcs: Api<VpcNetwork>,
    policies: Api<DynamicObject>,
    tunnels: Api<DynamicObject>,
    node: String,
}
async fn sync(
    g: &Guard,
    s: &Shared,
    previous: &mut Option<(BTreeSet<String>, BTreeSet<String>)>,
) -> Result<()> {
    let pods = g
        .pods
        .list(&ListParams::default().labels(VPC_LABEL))
        .await?;
    let vpcs = g.vpcs.list(&ListParams::default()).await?;
    let policies = g
        .policies
        .list(&ListParams::default().labels(&format!("app.kubernetes.io/managed-by={MANAGER}")))
        .await?;
    let tunnels = g.tunnels.list(&ListParams::default()).await?;
    let healthy: BTreeSet<_> = tunnels
        .items
        .iter()
        .filter(|t| {
            let heartbeat = t
                .data
                .pointer("/status/lastHeartbeatTime")
                .and_then(Value::as_str)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            t.data.pointer("/status/phase") == Some(&json!("Ready"))
                && heartbeat
                    .is_some_and(|t| chrono::Utc::now().signed_duration_since(t).num_seconds() < 20)
        })
        .map(ResourceExt::name_any)
        .collect();
    let mut managed = BTreeSet::new();
    let mut local = BTreeSet::new();
    let mut ready = BTreeMap::new();
    let mut markers = Vec::new();
    for p in pods.items {
        let labels = p.labels();
        let Some(id) = labels.get(VPC_LABEL) else {
            continue;
        };
        let ip = p
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_ref())
            .and_then(|ip| ip.parse::<IpAddr>().ok());
        let Some(IpAddr::V4(ip)) = ip else { continue };
        managed.insert(ip.to_string());
        let valid = vpcs.items.iter().find(|v| {
            v.spec.service_instance_id.to_string() == *id
                && labels.get(ORG_LABEL) == Some(&v.spec.organization_id.to_string())
                && v.metadata.deletion_timestamp.is_none()
        });
        if let Some(v) = valid {
            if v.spec.network.nat.enabled
                && healthy.contains(&g.node)
                && policies.items.iter().any(|e| {
                    e.name_any() == name(v.spec.service_instance_id)
                        && e.data.pointer("/status/node").and_then(Value::as_str)
                            == Some(g.node.as_str())
                })
            {
                local.insert(ip.to_string());
            }
            if p.spec.as_ref().and_then(|s| s.node_name.as_ref()) == Some(&g.node)
                && p.metadata.deletion_timestamp.is_none()
            {
                if let Some(uid) = p.uid() {
                    ready.insert(uid, IpAddr::V4(ip));
                }
                if labels.get(READY_LABEL) != Some(id) {
                    markers.push((
                        p.name_any(),
                        p.metadata.resource_version.clone(),
                        id.clone(),
                    ));
                }
            }
        }
    }
    let next = (managed, local);
    if previous.as_ref() != Some(&next) {
        set("HC-VPC-MANAGED", "hash:ip", &next.0).await?;
        *previous = Some(next.clone());
    }
    // Refresh expiring local permits even when the topology is unchanged.
    // If this daemon stops, kernel timeouts revoke its local NAT exits.
    set("HC-VPC-LOCAL", "hash:ip", &next.1).await?;
    for (pod, version, id) in markers {
        g.pods
            .patch(
                &pod,
                &PatchParams::default(),
                &Patch::Merge(
                    json!({"metadata":{"resourceVersion":version,"labels":{READY_LABEL:id}}}),
                ),
            )
            .await?;
    }
    *s.write().await = Snapshot {
        ready,
        at: Some(Instant::now()),
    };
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().json().init();
    let node = std::env::var("NODE_NAME")?;
    let ip: IpAddr = std::env::var("NODE_IP")?.parse()?;
    let bin = std::env::var("IPTABLES_BIN").unwrap_or_else(|_| "iptables-nft".into());
    ensure!(
        ["iptables", "iptables-nft", "iptables-legacy"].contains(&bin.as_str()),
        "invalid iptables backend"
    );
    let mut protected: BTreeSet<String> = resources::PROTECTED
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for cidr in std::env::var("VPC_PROTECTED_CIDRS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
    {
        let n: ipnet::IpNet = cidr.parse()?;
        ensure!(
            matches!(n, ipnet::IpNet::V4(_)),
            "IPv4 guard requires IPv4 protected CIDRs"
        );
        protected.insert(n.to_string());
    }
    install(&bin, &protected).await?;
    let client = Client::try_default().await?;
    let ns =
        std::env::var("FLASH_NAMESPACE").unwrap_or_else(|_| "heterocloud-flash-workloads".into());
    let g = Guard {
        pods: Api::namespaced(client.clone(), &ns),
        vpcs: Api::all(client.clone()),
        policies: Api::namespaced_with(
            client.clone(),
            &ns,
            &egress_resource("EgressPolicy", "egresspolicies"),
        ),
        tunnels: Api::all_with(client, &egress_resource("EgressTunnel", "egresstunnels")),
        node,
    };
    let state = Arc::new(RwLock::new(Snapshot::default()));
    let shared = state.clone();
    tokio::spawn(async move {
        let mut previous = None;
        loop {
            if let Err(e) = sync(&g, &shared, &mut previous).await {
                tracing::error!(error=%e,"NAT guard refresh failed; disabling local internet exit");
                *shared.write().await = Snapshot::default();
                if let Err(e) = set("HC-VPC-LOCAL", "hash:ip", &BTreeSet::new()).await {
                    tracing::error!(error=%e,"could not revoke local exit");
                }
                previous = None;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    let app = Router::new()
        .route("/ready", get(ready))
        .route("/health", get(health))
        .with_state(state);
    axum::serve(
        tokio::net::TcpListener::bind(SocketAddr::new(ip, 18083)).await?,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
