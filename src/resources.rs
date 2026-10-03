//! Pure desired-state compiler. All peer selectors carry both tenant and VPC identity.
use crate::{
    domain::{FlashVpcAttachment, VpcPeer, VpcRule},
    *,
};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use kube::{Resource, ResourceExt, api::DynamicObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Member {
    pub resource_name: String,
    pub uid: String,
    pub id: Uuid,
    pub organization: Uuid,
    pub project: Uuid,
    pub generation: i64,
    pub region: String,
    pub network: FlashVpcAttachment,
    pub ports: Vec<Port>,
    pub egress: Value,
}
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq)]
pub struct Port {
    pub name: String,
    pub protocol: FlashProtocol,
    pub container_port: u16,
}
impl Member {
    pub fn read(f: &DynamicObject) -> Result<Self> {
        let s = &f.data["spec"];
        let w = &s["workload"];
        Ok(Self {
            resource_name: f.name_any(),
            uid: f.uid().context("Flash UID missing")?,
            id: serde_json::from_value(s["service_instance_id"].clone())?,
            organization: serde_json::from_value(s["organization_id"].clone())?,
            project: serde_json::from_value(s["project_id"].clone())?,
            generation: s["desired_generation"]
                .as_i64()
                .context("Flash generation missing")?,
            region: w["region"].as_str().context("Flash region missing")?.into(),
            network: serde_json::from_value(w["network"].clone())?,
            ports: serde_json::from_value(w["ports"].clone())?,
            egress: w["egress"].clone(),
        })
    }
    pub fn private_name(&self) -> String {
        self.network
            .private_name
            .clone()
            .unwrap_or_else(|| format!("f-{}", self.id.simple()))
    }
    pub fn service_name(&self) -> String {
        format!("vpc-{}", self.id.simple())
    }
    pub fn belongs_to(&self, v: &VpcNetwork) -> bool {
        self.network.vpc_id == v.spec.service_instance_id
            && self.organization == v.spec.organization_id
            && self.project == v.spec.project_id
            && self.region == v.spec.network.region
            && self
                .network
                .security_groups
                .iter()
                .all(|g| v.spec.network.security_groups.contains(g))
    }
    fn matches(&self, peer: &VpcPeer) -> bool {
        match peer {
            VpcPeer::All => true,
            VpcPeer::Service { service_id } => self.id == *service_id,
            VpcPeer::SecurityGroup { name } => self.network.security_groups.contains(name),
        }
    }
}
pub fn labels(v: &VpcNetwork) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/managed-by".into(), MANAGER.into()),
        (VPC_LABEL.into(), v.spec.service_instance_id.to_string()),
        (ORG_LABEL.into(), v.spec.organization_id.to_string()),
    ])
}
pub fn owner(v: &VpcNetwork) -> Result<Value> {
    Ok(serde_json::to_value(
        v.controller_owner_ref(&()).context("VPC UID missing")?,
    )?)
}
pub fn metadata(v: &VpcNetwork, n: &str, ns: Option<&str>) -> Result<Value> {
    let mut m = json!({"name":n,"labels":labels(v),"ownerReferences":[owner(v)?]});
    if let Some(ns) = ns {
        m["namespace"] = json!(ns)
    }
    Ok(m)
}
pub fn selector(v: &VpcNetwork, ids: &[Uuid]) -> Value {
    json!({"matchLabels":{VPC_LABEL:v.spec.service_instance_id.to_string(),ORG_LABEL:v.spec.organization_id.to_string()},"matchExpressions":[{"key":INSTANCE_LABEL,"operator":"In","values":ids.iter().map(Uuid::to_string).collect::<Vec<_>>()}]})
}
fn peers(v: &VpcNetwork, members: &[Member], peer: &VpcPeer) -> Vec<Value> {
    let ids = members
        .iter()
        .filter(|m| m.belongs_to(v) && m.matches(peer))
        .map(|m| m.id)
        .collect::<Vec<_>>();
    if ids.is_empty() {
        Vec::new()
    } else {
        vec![json!({"podSelector":selector(v,&ids)})]
    }
}
fn port_in_rule(p: &Port, r: &VpcRule) -> bool {
    p.protocol == r.protocol
        && p.container_port >= r.port
        && p.container_port <= r.end_port.unwrap_or(r.port)
}
fn ports_for(member: &Member, rule: &VpcRule) -> Vec<Value> {
    let ports: BTreeSet<_> = member
        .ports
        .iter()
        .filter(|p| port_in_rule(p, rule))
        .map(|p| p.container_port)
        .collect();
    ports
        .into_iter()
        .map(|port| json!({"protocol":rule.protocol.kubernetes(),"port":port}))
        .collect()
}
pub fn connection_policy(
    v: &VpcNetwork,
    member: &Member,
    members: &[Member],
    ns: &str,
) -> Result<Value> {
    ensure!(member.belongs_to(v), "invalid VPC attachment");
    let mut ingress = Vec::new();
    let mut egress = Vec::new();
    for rule in &v.spec.network.rules {
        if member.matches(&rule.destination) {
            let from = peers(v, members, &rule.source);
            let ports = ports_for(member, rule);
            if !from.is_empty() && !ports.is_empty() {
                ingress.push(json!({"from":from,"ports":ports}));
            }
        }
        if member.matches(&rule.source) {
            // Separate destinations to avoid granting a port declared by a different target.
            for target in members
                .iter()
                .filter(|m| m.belongs_to(v) && m.matches(&rule.destination))
            {
                let ports = ports_for(target, rule);
                if !ports.is_empty() {
                    egress.push(
                        json!({"to":[{"podSelector":selector(v,&[target.id])}],"ports":ports}),
                    );
                }
            }
        }
    }
    Ok(
        json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":metadata(v,&member.service_name(),Some(ns))?,"spec":{"podSelector":selector(v,&[member.id]),"policyTypes":["Ingress","Egress"],"ingress":ingress,"egress":egress}}),
    )
}
pub const PROTECTED: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/3",
];
pub fn public_destinations(egress: &Value, protected: &[IpNet]) -> Result<Vec<Value>> {
    let mode = egress["mode"].as_str().unwrap_or("internet");
    if mode == "disabled" {
        return Ok(Vec::new());
    }
    ensure!(
        mode == "internet" || mode == "restricted",
        "invalid egress mode"
    );
    let allowed: Vec<String> = serde_json::from_value(
        egress
            .get("allowed_destination_cidrs")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )?;
    let denied: Vec<String> = serde_json::from_value(
        egress
            .get("denied_destination_cidrs")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )?;
    let roots = if mode == "internet" {
        vec!["0.0.0.0/0".into()]
    } else {
        allowed
    };
    let mut excluded = PROTECTED
        .iter()
        .map(|s| s.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()?;
    excluded.extend(protected.iter().copied());
    for d in denied {
        excluded.push(d.parse()?)
    }
    let mut out = Vec::new();
    for r in roots {
        let cidr: IpNet = r.parse()?;
        // The deployed NAT transport is IPv4. Never allow an IPv6 bypass.
        if !matches!(cidr, IpNet::V4(_)) || excluded.iter().any(|n| n.contains(&cidr)) {
            continue;
        }
        let except = excluded
            .iter()
            .filter(|n| cidr.contains(*n))
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        out.push(json!({"ipBlock":{"cidr":cidr.to_string(),"except":except}}));
    }
    Ok(out)
}
pub fn nat_policy(v: &VpcNetwork, m: &Member, ns: &str, protected: &[IpNet]) -> Result<Value> {
    let mut sel = selector(v, &[m.id]);
    sel["matchLabels"][READY_LABEL] = json!(v.spec.service_instance_id.to_string());
    let to = if v.spec.network.nat.enabled {
        public_destinations(&m.egress, protected)?
    } else {
        Vec::new()
    };
    let egress = if to.is_empty() {
        vec![]
    } else {
        vec![json!({"to":to})]
    };
    Ok(
        json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":metadata(v,&format!("{}-nat",m.service_name()),Some(ns))?,"spec":{"podSelector":sel,"policyTypes":["Egress"],"egress":egress}}),
    )
}
pub fn private_service(v: &VpcNetwork, m: &Member, ns: &str) -> Result<Value> {
    let mut seen = BTreeSet::new();
    let ports=m.ports.iter().filter(|p|seen.insert((p.protocol.kubernetes(),p.container_port))).map(|p|json!({"name":p.name,"protocol":p.protocol.kubernetes(),"port":p.container_port,"targetPort":p.container_port})).collect::<Vec<_>>();
    Ok(
        json!({"apiVersion":"v1","kind":"Service","metadata":metadata(v,&m.service_name(),Some(ns))?,"spec":{"type":"ClusterIP","selector":{VPC_LABEL:v.spec.service_instance_id.to_string(),ORG_LABEL:v.spec.organization_id.to_string(),INSTANCE_LABEL:m.id.to_string()},"ports":ports}}),
    )
}
pub fn private_alias(v: &VpcNetwork, m: &Member, ns: &str, domain: &str) -> Result<Value> {
    Ok(
        json!({"apiVersion":"v1","kind":"Service","metadata":metadata(v,&m.private_name(),Some(&name(v.spec.service_instance_id)))?,"spec":{"type":"ExternalName","externalName":format!("{}.{}.svc.{}",m.service_name(),ns,domain)}}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> Result<(VpcNetwork, Vec<Member>)> {
        let id = Uuid::from_u128(10);
        let org = Uuid::from_u128(11);
        let project = Uuid::from_u128(12);
        let mut v = VpcNetwork::new(
            &name(id),
            VpcNetworkSpec {
                desired_generation: 1,
                organization_id: org,
                project_id: project,
                service_instance_id: id,
                display_name: "test".into(),
                network: serde_json::from_value(
                    json!({"region":"test","security_groups":["parent","child"],"rules":[{"source":{"type":"security_group","name":"parent"},"destination":{"type":"security_group","name":"child"},"port":22,"protocol":"tcp"}]}),
                )?,
            },
        );
        v.metadata.uid = Some("test".into());
        let mut ms = Vec::new();
        for (i, group) in ["parent", "child", "child"].into_iter().enumerate() {
            ms.push(Member {
                resource_name: format!("flash-{i}"),
                uid: format!("uid-{i}"),
                id: Uuid::from_u128(20 + i as u128),
                organization: org,
                project,
                generation: 1,
                region: "test".into(),
                network: FlashVpcAttachment {
                    vpc_id: id,
                    security_groups: vec![group.into()],
                    private_name: None,
                },
                ports: vec![Port {
                    name: "ssh".into(),
                    protocol: FlashProtocol::Tcp,
                    container_port: 22,
                }],
                egress: json!({"mode":"internet"}),
            });
        }
        Ok((v, ms))
    }
    #[test]
    fn rules_are_directional_port_and_tenant_scoped() -> Result<()> {
        let (v, mut ms) = setup()?;
        ms[2].organization = Uuid::from_u128(99);
        let parent = connection_policy(&v, &ms[0], &ms, "flash")?;
        assert_eq!(parent["spec"]["ingress"], json!([]));
        assert_eq!(parent["spec"]["egress"].as_array().map(Vec::len), Some(1));
        let e = &parent["spec"]["egress"][0];
        assert_eq!(e["ports"], json!([{"protocol":"TCP","port":22}]));
        assert_eq!(
            e["to"][0]["podSelector"]["matchLabels"][VPC_LABEL],
            v.spec.service_instance_id.to_string()
        );
        let child = connection_policy(&v, &ms[1], &ms, "flash")?;
        assert_eq!(child["spec"]["egress"], json!([]));
        assert_eq!(child["spec"]["ingress"].as_array().map(Vec::len), Some(1));
        Ok(())
    }
    #[test]
    fn revoked_group_and_undeclared_port_do_not_grant_access() -> Result<()> {
        let (mut v, mut ms) = setup()?;
        v.spec.network.rules[0].port = 23;
        assert_eq!(
            connection_policy(&v, &ms[1], &ms, "flash")?["spec"]["ingress"],
            json!([])
        );
        v.spec.network.rules[0].port = 22;
        ms[1].network.security_groups = vec!["parent".into()];
        assert_eq!(
            connection_policy(&v, &ms[1], &ms, "flash")?["spec"]["ingress"],
            json!([])
        );
        Ok(())
    }
    #[test]
    fn nat_requires_enabled_gateway_and_guard_label() -> Result<()> {
        let (mut v, ms) = setup()?;
        let off = nat_policy(&v, &ms[0], "flash", &[])?;
        assert_eq!(off["spec"]["egress"], json!([]));
        v.spec.network.nat.enabled = true;
        let on = nat_policy(&v, &ms[0], "flash", &["203.0.113.0/24".parse()?])?;
        assert_eq!(
            on["spec"]["podSelector"]["matchLabels"][READY_LABEL],
            v.spec.service_instance_id.to_string()
        );
        let except = &on["spec"]["egress"][0]["to"][0]["ipBlock"]["except"];
        assert!(
            except
                .as_array()
                .context("except")?
                .contains(&json!("10.0.0.0/8"))
        );
        assert!(
            except
                .as_array()
                .context("except")?
                .contains(&json!("203.0.113.0/24"))
        );
        Ok(())
    }
    #[test]
    fn restricted_nat_never_permits_private_or_ipv6_destinations() -> Result<()> {
        let e = json!({"mode":"restricted","allowed_destination_cidrs":["10.0.0.0/8","2000::/3","198.51.100.0/24"],"denied_destination_cidrs":["198.51.100.128/25"]});
        let d = public_destinations(&e, &[])?;
        assert_eq!(
            d,
            json!([{"ipBlock":{"cidr":"198.51.100.0/24","except":["198.51.100.128/25"]}}])
                .as_array()
                .context("array")?
                .clone()
        );
        Ok(())
    }
}
