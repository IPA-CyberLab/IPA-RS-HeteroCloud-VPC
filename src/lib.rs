pub mod auth;
pub mod controller;
pub mod domain;
pub mod resources;
use kube::{
    CustomResource,
    api::{ApiResource, DynamicObject, GroupVersionKind},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("{0}")]
    InvalidVpcSpec(String),
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FlashProtocol {
    Tcp,
    Udp,
}
impl FlashProtocol {
    pub fn kubernetes(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, CustomResource)]
#[kube(
    group = "vpc.heterocloud.io",
    version = "v1alpha1",
    kind = "VpcNetwork",
    plural = "vpcnetworks",
    shortname = "vpc",
    status = "VpcStatus"
)]
#[serde(deny_unknown_fields)]
pub struct VpcNetworkSpec {
    pub desired_generation: i64,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub display_name: String,
    pub network: domain::VpcSpec,
}
#[derive(Clone, Default, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct VpcStatus {
    pub observed_generation: i64,
    pub phase: String,
    pub message: String,
    pub dns_suffix: String,
    pub nat_enabled: bool,
    pub nat_gateway_node: Option<String>,
    pub attachments: Vec<VpcAttachmentStatus>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct VpcAttachmentStatus {
    pub service_instance_id: Uuid,
    pub private_dns: String,
    pub private_ip: Option<String>,
    pub security_groups: Vec<String>,
    pub ports: Vec<resources::Port>,
}
pub const MANAGER: &str = "heterocloud-vpc";
pub const VPC_LABEL: &str = "vpc.heterocloud.io/network";
pub const READY_LABEL: &str = "vpc.heterocloud.io/egress-ready";
pub const INSTANCE_LABEL: &str = "flash.heterocloud.io/instance";
pub const ORG_LABEL: &str = "flash.heterocloud.io/organization";
pub fn name(id: Uuid) -> String {
    format!("hc-vpc-{}", id.simple())
}
pub fn resource(group: &str, version: &str, kind: &str, plural: &str) -> ApiResource {
    let mut ar = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
    ar.plural = plural.into();
    ar
}
pub fn flash_resource() -> ApiResource {
    resource(
        "flash.heterocloud.io",
        "v1alpha1",
        "FlashService",
        "flashservices",
    )
}
pub fn egress_resource(kind: &str, plural: &str) -> ApiResource {
    resource("egressgateway.spidernet.io", "v1beta1", kind, plural)
}
pub fn flash_vpc(flash: &DynamicObject) -> Option<Uuid> {
    flash
        .data
        .pointer("/spec/workload/network/vpc_id")?
        .as_str()?
        .parse()
        .ok()
}
