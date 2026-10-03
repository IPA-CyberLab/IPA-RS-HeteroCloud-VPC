use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use heterocloud_vpc::{
    auth::{ProviderAuthenticator, ProviderClaims},
    *,
};
use kube::{
    Api, Client, ResourceExt,
    api::{DeleteParams, DynamicObject, ListParams, PostParams},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
struct App {
    vpcs: Api<VpcNetwork>,
    flashes: Api<DynamicObject>,
    auth: ProviderAuthenticator,
}
struct Error(StatusCode, String);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":{"message":self.1}}))).into_response()
    }
}
impl From<kube::Error> for Error {
    fn from(e: kube::Error) -> Self {
        tracing::error!(error=%e,"Kubernetes request failed");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "network control plane is temporarily unavailable".into(),
        )
    }
}
fn conflict(message: &str) -> Error {
    Error(StatusCode::CONFLICT, message.into())
}
fn claims(s: &App, h: &HeaderMap, id: Uuid, action: &str) -> Result<ProviderClaims, Error> {
    let c = s.auth.authenticate(h, action).map_err(|_| {
        Error(
            StatusCode::UNAUTHORIZED,
            "provider authentication failed".into(),
        )
    })?;
    if c.service_instance_id != id || c.organization_id.is_nil() || c.project_id.is_nil() {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "provider context mismatch".into(),
        ));
    }
    Ok(c)
}
fn owned(v: &VpcNetwork, c: &ProviderClaims) -> Result<(), Error> {
    if v.spec.organization_id != c.organization_id
        || v.spec.project_id != c.project_id
        || v.spec.service_instance_id != c.service_instance_id
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "provider context mismatch".into(),
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    generation: i64,
    name: String,
    spec: domain::VpcSpec,
    #[serde(default)]
    policy: Option<Value>,
}
async fn reconcile(
    State(s): State<Arc<App>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<Request>,
) -> Result<impl IntoResponse, Error> {
    let c = claims(&s, &headers, id, "service-instance.reconcile")?;
    req.spec
        .validate()
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    if req.name.trim().is_empty() || req.name.chars().count() > 120 || req.policy.is_some() {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "invalid provider request".into(),
        ));
    }
    if req.generation != c.generation {
        return Err(conflict("generation mismatch"));
    }
    let n = name(id);
    let desired = VpcNetworkSpec {
        desired_generation: c.generation,
        organization_id: c.organization_id,
        project_id: c.project_id,
        service_instance_id: id,
        display_name: req.name,
        network: req.spec,
    };
    let mut created = VpcNetwork::new(&n, desired.clone());
    created.metadata.finalizers = Some(vec!["vpc.heterocloud.io/replay-window".into()]);
    let v = match s.vpcs.get_opt(&n).await? {
        None => match s.vpcs.create(&PostParams::default(), &created).await {
            Ok(v) => v,
            Err(kube::Error::Api(e)) if e.code == 409 => {
                return Err(Error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "concurrent creation; retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        },
        Some(mut v) => {
            owned(&v, &c)?;
            if v.metadata.deletion_timestamp.is_some() {
                return Err(conflict("VPC is deleting"));
            }
            if c.generation < v.spec.desired_generation {
                return Err(conflict("stale generation"));
            }
            if c.generation == v.spec.desired_generation {
                if serde_json::to_value(&v.spec).ok() != serde_json::to_value(&desired).ok() {
                    return Err(conflict("generation has different desired state"));
                }
                v
            } else {
                v.spec = desired;
                // Resource version precondition prevents an older command overwriting a newer one.
                match s.vpcs.replace(&n, &PostParams::default(), &v).await {
                    Ok(v) => v,
                    Err(kube::Error::Api(e)) if e.code == 409 => {
                        return Err(Error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "concurrent update; retry".into(),
                        ));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    };
    let status = v.status.unwrap_or_default();
    if status.observed_generation != c.generation || status.phase != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("VPC is converging: {}", status.message),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"operation_id":Uuid::new_v5(&id,format!("reconcile:{}",c.generation).as_bytes()),"status":status}),
        ),
    ))
}
async fn remove(
    State(s): State<Arc<App>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Error> {
    let c = claims(&s, &headers, id, "service-instance.delete")?;
    if let Some(v) = s.vpcs.get_opt(&name(id)).await? {
        owned(&v, &c)?;
        if c.generation < v.spec.desired_generation {
            return Err(conflict("stale generation"));
        }
        let members = s.flashes.list(&ListParams::default()).await?;
        if members.items.iter().any(|f| flash_vpc(f) == Some(id)) {
            return Err(conflict("VPC still has attached services"));
        }
        let params = DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: v.metadata.uid.clone(),
                resource_version: v.metadata.resource_version.clone(),
            }),
            propagation_policy: Some(kube::api::PropagationPolicy::Foreground),
            ..Default::default()
        };
        if v.metadata.deletion_timestamp.is_none() {
            s.vpcs.delete(&v.name_any(), &params).await?;
        }
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "waiting for VPC resources to be removed".into(),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"operation_id":Uuid::new_v5(&id,format!("delete:{}",c.generation).as_bytes()),"status":{"phase":"deleted"}}),
        ),
    ))
}
async fn status(
    State(s): State<Arc<App>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let c = claims(&s, &headers, id, "vpc.status.get")?;
    let v = s
        .vpcs
        .get_opt(&name(id))
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "VPC not found".into()))?;
    owned(&v, &c)?;
    Ok(Json(
        json!({"generation":v.spec.desired_generation,"status":v.status}),
    ))
}
async fn ready(State(s): State<Arc<App>>) -> Result<StatusCode, Error> {
    s.vpcs.list(&ListParams::default().limit(1)).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt().json().init();
    let client = Client::try_default().await?;
    let ns = env::var("FLASH_NAMESPACE").unwrap_or_else(|_| "heterocloud-flash-workloads".into());
    let s = Arc::new(App {
        vpcs: Api::all(client.clone()),
        flashes: Api::namespaced_with(client, &ns, &flash_resource()),
        auth: ProviderAuthenticator::from_public_keys_json(
            env::var("HETEROCLOUD_PROVIDER_ISSUER")?,
            "heterocloud-vpc",
            &env::var("HETEROCLOUD_PROVIDER_PUBLIC_KEYS_JSON")?,
        )?,
    });
    let app = Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health/ready", get(ready))
        .route(
            "/internal/v1/service-instances/{id}",
            put(reconcile).delete(remove).get(status),
        )
        .with_state(s);
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:8080").await?, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
