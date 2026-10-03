use kube::CustomResourceExt;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "{}",
        serde_yaml::to_string(&heterocloud_vpc::VpcNetwork::crd())?
    );
    Ok(())
}
