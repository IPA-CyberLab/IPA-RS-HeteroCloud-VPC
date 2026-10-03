use heterocloud_vpc::controller::{Config, run};
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
    tokio::select! {result=run(c)=>result, _=tokio::signal::ctrl_c()=>Ok(())}
}
