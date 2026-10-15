use heterocloud_vpc::{
    controller::{Config, run},
    leader,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().json().init();
    let protected = std::env::var("VPC_PROTECTED_CIDRS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let c = Config {
        client: kube::Client::try_default().await?,
        namespace: std::env::var("FLASH_NAMESPACE")
            .unwrap_or_else(|_| "heterocloud-flash-workloads".into()),
        cluster_domain: std::env::var("CLUSTER_DOMAIN").unwrap_or_else(|_| "cluster.local".into()),
        gateway_selector: serde_json::from_str(&std::env::var("VPC_GATEWAY_SELECTOR_JSON")?)?,
        protected,
    };
    let namespace = std::env::var("POD_NAMESPACE")?;
    let identity = format!("{}-{}", std::env::var("POD_UID")?, uuid::Uuid::now_v7());
    let leases = kube::Api::namespaced(c.client.clone(), &namespace);
    let ready = Arc::new(AtomicBool::new(false));
    let readiness = ready.clone();
    let health = axum::Router::new()
        .route(
            "/health/live",
            axum::routing::get(|| async { http::StatusCode::OK }),
        )
        .route(
            "/health/ready",
            axum::routing::get(move || {
                let state = readiness.clone();
                async move {
                    if state.load(Ordering::Acquire) {
                        http::StatusCode::OK
                    } else {
                        http::StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082").await?;
    let shutdown = async {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=async {if let Some(signal)=&mut term {signal.recv().await;}else{std::future::pending::<()>().await;}}=>{} }
    };
    tokio::select! {
        result=leader::supervise(leases,identity,run(c),shutdown,ready)=>result,
        result=axum::serve(listener,health)=>{result?; Ok(())}
    }
}
