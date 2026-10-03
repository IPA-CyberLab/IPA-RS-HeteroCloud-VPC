use crate::{resources::*, *};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use kube::{
    Api, Client, ResourceExt,
    api::{ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

#[derive(Clone)]
pub struct Config {
    pub client: Client,
    pub namespace: String,
    pub cluster_domain: String,
    pub gateway_selector: Value,
    pub protected: Vec<IpNet>,
}
async fn apply(
    c: &Config,
    ar: &ApiResource,
    ns: Option<&str>,
    mut v: Value,
) -> Result<DynamicObject> {
    // Kubernetes omits empty rule arrays; omit them too to avoid generation churn.
    if v["kind"] == "NetworkPolicy" {
        for key in ["ingress", "egress"] {
            if v["spec"][key].as_array().is_some_and(Vec::is_empty)
                && let Some(spec) = v["spec"].as_object_mut()
            {
                spec.remove(key);
            }
        }
    }
    let api: Api<DynamicObject> = match ns {
        Some(ns) => Api::namespaced_with(c.client.clone(), ns, ar),
        None => Api::all_with(c.client.clone(), ar),
    };
    let name = v["metadata"]["name"]
        .as_str()
        .context("resource name missing")?
        .to_owned();
    Ok(api
        .patch(
            &name,
            &PatchParams::apply(MANAGER).force(),
            &Patch::Apply(v),
        )
        .await?)
}
async fn prune(
    c: &Config,
    ar: &ApiResource,
    ns: Option<&str>,
    v: &VpcNetwork,
    keep: &BTreeSet<String>,
) -> Result<()> {
    let api: Api<DynamicObject> = match ns {
        Some(ns) => Api::namespaced_with(c.client.clone(), ns, ar),
        None => Api::all_with(c.client.clone(), ar),
    };
    for r in api
        .list(&ListParams::default().labels(&format!(
            "app.kubernetes.io/managed-by={MANAGER},{VPC_LABEL}={}",
            v.spec.service_instance_id
        )))
        .await?
        .items
    {
        if !keep.contains(&r.name_any()) {
            delete(&api, &r.name_any()).await?;
        }
    }
    Ok(())
}
async fn delete(api: &Api<DynamicObject>, n: &str) -> Result<()> {
    match api.delete(n, &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}
pub async fn reconcile(c: &Config, v: &VpcNetwork, flashes: &[DynamicObject]) -> Result<VpcStatus> {
    v.spec.network.validate()?;
    let id = v.spec.service_instance_id;
    let n = name(id);
    let members = flashes
        .iter()
        .filter(|f| flash_vpc(f) == Some(id) && f.metadata.deletion_timestamp.is_none())
        .map(Member::read)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        members.iter().all(|m| m.belongs_to(v)),
        "VPC contains an invalid tenant, project, region or group reference"
    );
    let mut names = BTreeSet::new();
    ensure!(
        members.iter().all(|m| names.insert(m.private_name())),
        "duplicate private DNS names"
    );
    let svc = resource("", "v1", "Service", "services");
    let netpol = resource(
        "networking.k8s.io",
        "v1",
        "NetworkPolicy",
        "networkpolicies",
    );
    let ns_ar = resource("", "v1", "Namespace", "namespaces");
    let mut namespace =
        json!({"apiVersion":"v1","kind":"Namespace","metadata":metadata(v,&n,None)?});
    namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = json!("restricted");
    apply(c, &ns_ar, None, namespace).await?;
    // These namespaces contain DNS aliases only. A default-deny policy also
    // prevents future accidental workloads from communicating without a rule.
    apply(c,&netpol,Some(&n),json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":metadata(v,"default-deny",Some(&n))?,"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}})).await?;
    let mut policies = BTreeSet::new();
    let mut services = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    for m in &members {
        policies.insert(m.service_name());
        policies.insert(format!("{}-nat", m.service_name()));
        if !m.ports.is_empty() {
            services.insert(m.service_name());
            aliases.insert(m.private_name());
        }
    }
    // Revoke stale attachments and aliases before publishing replacements.
    prune(c, &netpol, Some(&c.namespace), v, &policies).await?;
    prune(c, &svc, Some(&c.namespace), v, &services).await?;
    prune(c, &svc, Some(&n), v, &aliases).await?;
    // Disable egress grants before removing a gateway, never after.
    for m in &members {
        apply(
            c,
            &netpol,
            Some(&c.namespace),
            nat_policy(v, m, &c.namespace, &c.protected)?,
        )
        .await?;
    }
    let gw_ar = egress_resource("EgressGateway", "egressgateways");
    let ep_ar = egress_resource("EgressPolicy", "egresspolicies");
    let gw_api: Api<DynamicObject> = Api::all_with(c.client.clone(), &gw_ar);
    let ep_api: Api<DynamicObject> = Api::namespaced_with(c.client.clone(), &c.namespace, &ep_ar);
    let mut gateway_node = None;
    if v.spec.network.nat.enabled {
        let gateway=apply(c,&gw_ar,None,json!({"apiVersion":"egressgateway.spidernet.io/v1beta1","kind":"EgressGateway","metadata":metadata(v,&n,None)?,"spec":{"nodeSelector":{"selector":c.gateway_selector}}})).await?;
        let policy=apply(c,&ep_ar,Some(&c.namespace),json!({"apiVersion":"egressgateway.spidernet.io/v1beta1","kind":"EgressPolicy","metadata":metadata(v,&n,Some(&c.namespace))?,"spec":{"egressGatewayName":n,"egressIP":{"useNodeIP":true},"appliedTo":{"podSelector":{"matchLabels":{VPC_LABEL:id.to_string(),ORG_LABEL:v.spec.organization_id.to_string()}}}}})).await?;
        gateway_node = policy
            .data
            .pointer("/status/node")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
        if let Some(node) = &gateway_node {
            let ready = gateway
                .data
                .pointer("/status/nodeList")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|x| x["name"] == *node && x["status"] == "Ready")
                });
            if !ready {
                gateway_node = None;
            }
        }
    } else {
        delete(&ep_api, &n).await?;
        delete(&gw_api, &n).await?;
    }
    let mut attachments = Vec::new();
    let flash_api: Api<DynamicObject> =
        Api::namespaced_with(c.client.clone(), &c.namespace, &flash_resource());
    for m in &members {
        apply(
            c,
            &netpol,
            Some(&c.namespace),
            connection_policy(v, m, &members, &c.namespace)?,
        )
        .await?;
        let dns = format!("{}.{}.svc.{}", m.private_name(), n, c.cluster_domain);
        let mut cluster_ip = None;
        if !m.ports.is_empty() {
            let service = apply(
                c,
                &svc,
                Some(&c.namespace),
                private_service(v, m, &c.namespace)?,
            )
            .await?;
            cluster_ip = service
                .data
                .pointer("/spec/clusterIP")
                .and_then(Value::as_str)
                .map(str::to_owned);
            apply(
                c,
                &svc,
                Some(&n),
                private_alias(v, m, &c.namespace, &c.cluster_domain)?,
            )
            .await?;
        }
        attachments.push(VpcAttachmentStatus {
            service_instance_id: m.id,
            private_dns: dns.clone(),
            private_ip: cluster_ip.clone(),
            security_groups: m.network.security_groups.clone(),
            ports: m.ports.clone(),
        });
        // Flash readiness includes installation of its VPC policies and DNS.
        let annotations = json!({"vpc.heterocloud.io/applied-generation":m.generation.to_string(),"vpc.heterocloud.io/private-dns":dns,"vpc.heterocloud.io/private-ip":cluster_ip.unwrap_or_default()});
        if let Some(f) = flashes.iter().find(|f| f.name_any() == m.resource_name) {
            let current = serde_json::to_value(f.annotations())?;
            if annotations
                .as_object()
                .context("annotations")?
                .iter()
                .any(|(k, v)| current.get(k) != Some(v))
            {
                flash_api.patch(&m.resource_name,&PatchParams::default(),&Patch::Merge(json!({"metadata":{"resourceVersion":f.metadata.resource_version,"annotations":annotations}}))).await?;
            }
        }
    }
    let ready = !v.spec.network.nat.enabled || gateway_node.is_some();
    Ok(VpcStatus {
        observed_generation: v.spec.desired_generation,
        phase: if ready { "ready" } else { "provisioning" }.into(),
        message: if ready {
            "private DNS and connection policies applied"
        } else {
            "waiting for a healthy NAT gateway"
        }
        .into(),
        dns_suffix: format!("{n}.svc.{}", c.cluster_domain),
        nat_enabled: v.spec.network.nat.enabled,
        nat_gateway_node: gateway_node,
        attachments,
    })
}
pub async fn run(c: Config) -> Result<()> {
    let vpcs: Api<VpcNetwork> = Api::all(c.client.clone());
    let flashes: Api<DynamicObject> =
        Api::namespaced_with(c.client.clone(), &c.namespace, &flash_resource());
    loop {
        let result:Result<()>=async {
            let fs=flashes.list(&ListParams::default()).await?;
            for v in vpcs.list(&ListParams::default()).await?.items {
                if let Some(deleted_at) = &v.metadata.deletion_timestamp {
                    // An in-flight older PUT cannot resurrect a deleted network.
                    if chrono::Utc::now().timestamp().saturating_sub(deleted_at.0.as_second()) > 65 {
                        let finalizers = v.finalizers().iter().filter(|f| f.as_str() != "vpc.heterocloud.io/replay-window").cloned().collect::<Vec<_>>();
                        if finalizers.len() != v.finalizers().len() {
                            vpcs.patch(&v.name_any(), &PatchParams::default(), &Patch::Merge(json!({"metadata":{"resourceVersion":v.metadata.resource_version,"finalizers":finalizers}}))).await?;
                        }
                    }
                    continue;
                }
                let s=match reconcile(&c,&v,&fs.items).await {Ok(s)=>s,Err(e)=>{tracing::error!(network=%v.name_any(),error=%e,"VPC reconciliation failed");VpcStatus{phase:"provisioning".into(),message:e.to_string(),observed_generation:v.spec.desired_generation,..Default::default()}}};
                if v.status.as_ref()!=Some(&s) {
                    vpcs.patch_status(&v.name_any(),&PatchParams::default(),&Patch::Merge(json!({"metadata":{"resourceVersion":v.metadata.resource_version},"status":s}))).await?;
                }
            } Ok(())
        }.await;
        if let Err(e) = result {
            tracing::error!(error=%e,"VPC reconciliation iteration failed");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
