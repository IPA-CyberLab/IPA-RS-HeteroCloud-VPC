//! Lease election with a monotonic observation window and bounded renewal.
use anyhow::{Result, ensure};
use k8s_openapi::{api::coordination::v1::Lease, apimachinery::pkg::apis::meta::v1::MicroTime};
use kube::{Api, api::PostParams};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::{Instant, interval, sleep, sleep_until, timeout};

const NAME: &str = "heterocloud-vpc-controller";
const DURATION: i32 = 15;
const RETRY: Duration = Duration::from_secs(2);
const REQUEST: Duration = Duration::from_secs(3);
const DEADLINE: Duration = Duration::from_secs(8);

#[derive(Default)]
struct Observed {
    record: String,
    since: Option<Instant>,
}

impl Observed {
    fn expired(&mut self, lease: &Lease) -> Result<bool> {
        let record = serde_json::to_string(&lease.spec)?;
        if self.record != record {
            self.record = record;
            self.since = Some(Instant::now());
        }
        let seconds = lease
            .spec
            .as_ref()
            .and_then(|s| s.lease_duration_seconds)
            .unwrap_or(DURATION);
        ensure!(
            (1..=60).contains(&seconds),
            "unexpected election lease duration"
        );
        Ok(self
            .since
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(seconds as u64)))
    }
}

async fn attempt(api: &Api<Lease>, identity: &str, observed: &mut Observed) -> Result<bool> {
    let existing = api.get_opt(NAME).await?;
    let mut lease = existing.clone().unwrap_or_else(|| Lease {
        metadata: kube::api::ObjectMeta {
            name: Some(NAME.into()),
            ..Default::default()
        },
        ..Default::default()
    });
    let spec = lease.spec.get_or_insert_default();
    let ours = spec.holder_identity.as_deref() == Some(identity);
    let occupied = spec
        .holder_identity
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    if occupied && !ours && !observed.expired(&lease)? {
        return Ok(false);
    }
    let now: MicroTime = serde_json::from_value(serde_json::json!(
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    ))?;
    let spec = lease.spec.get_or_insert_default();
    if !ours {
        spec.acquire_time = Some(now.clone());
        spec.lease_transitions = Some(spec.lease_transitions.unwrap_or(0).saturating_add(1));
    }
    spec.holder_identity = Some(identity.into());
    spec.lease_duration_seconds = Some(DURATION);
    spec.renew_time = Some(now);
    let write = if existing.is_some() {
        api.replace(NAME, &PostParams::default(), &lease).await
    } else {
        api.create(&PostParams::default(), &lease).await
    };
    match write {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn release(api: &Api<Lease>, identity: &str) -> Result<()> {
    if let Some(mut lease) = api.get_opt(NAME).await?
        && let Some(spec) = &mut lease.spec
        && spec.holder_identity.as_deref() == Some(identity)
    {
        spec.holder_identity = None;
        api.replace(NAME, &PostParams::default(), &lease).await?;
    }
    Ok(())
}

pub async fn supervise<F, S>(
    api: Api<Lease>,
    identity: String,
    work: F,
    shutdown: S,
    ready: Arc<AtomicBool>,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send,
    S: Future<Output = ()> + Send,
{
    let mut observed = Observed::default();
    tokio::pin!(shutdown);
    loop {
        tokio::select! { biased;
            () = &mut shutdown => return Ok(()),
            () = sleep(RETRY) => {}
        }
        match timeout(REQUEST, attempt(&api, &identity, &mut observed)).await {
            Ok(Ok(acquired)) => {
                ready.store(true, Ordering::Release);
                if acquired {
                    break;
                }
            }
            _ => {
                ready.store(false, Ordering::Release);
                tracing::warn!("VPC election API unavailable");
            }
        }
    }
    tracing::info!(%identity, "VPC controller leadership acquired");
    let mut work = Box::pin(work);
    let mut heartbeat = interval(RETRY);
    let mut renewed = Instant::now();
    let result = loop {
        tokio::select! { biased;
            () = &mut shutdown => break Ok(()),
            () = sleep_until(renewed + DEADLINE) => break Err(anyhow::anyhow!("VPC lease renewal deadline elapsed")),
            _ = heartbeat.tick() => {
                match timeout(REQUEST, attempt(&api, &identity, &mut observed)).await {
                    Ok(Ok(true)) => { renewed = Instant::now(); ready.store(true, Ordering::Release); }
                    Ok(Ok(false)) => break Err(anyhow::anyhow!("VPC controller lease lost")),
                    _ => { ready.store(false, Ordering::Release); }
                }
            }
            result = &mut work => break result,
        }
    };
    // Stop all reconciliation before releasing. A crash retains the lease until
    // its observation window expires; standby never starts from wall-clock skew.
    drop(work);
    ready.store(false, Ordering::Release);
    let _ = timeout(REQUEST, release(&api, &identity)).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn other_holder_is_not_expired_on_first_observation() -> Result<()> {
        let lease: Lease = serde_json::from_value(
            serde_json::json!({"metadata":{"name":NAME},"spec":{"holderIdentity":"other","leaseDurationSeconds":15,"renewTime":"2000-01-01T00:00:00Z"}}),
        )?;
        assert!(!Observed::default().expired(&lease)?);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an isolated real Kubernetes API and VPC_LEASE_E2E=1"]
    async fn real_lease_prevents_overlap_and_recovers_from_leader_crash() -> Result<()> {
        if std::env::var("VPC_LEASE_E2E").as_deref() != Ok("1") {
            anyhow::bail!("explicit isolated election E2E required");
        }
        use k8s_openapi::api::core::v1::Namespace;
        let client = kube::Client::try_default().await?;
        let name = format!("vpc-lease-e2e-{}", uuid::Uuid::now_v7());
        let namespaces: Api<Namespace> = Api::all(client.clone());
        namespaces
            .create(
                &PostParams::default(),
                &Namespace {
                    metadata: kube::api::ObjectMeta {
                        name: Some(name.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await?;
        let api: Api<Lease> = Api::namespaced(client, &name);
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(AtomicUsize::new(0));
        let overlap = Arc::new(AtomicBool::new(false));
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let mut tasks = Vec::new();
        for id in ["one", "two"] {
            let (active, starts, overlap) = (active.clone(), starts.clone(), overlap.clone());
            let work = async move {
                if active.fetch_add(1, Ordering::SeqCst) != 0 {
                    overlap.store(true, Ordering::SeqCst);
                }
                let _guard = Guard(active);
                starts.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<()>>().await
            };
            tasks.push(tokio::spawn(supervise(
                api.clone(),
                id.into(),
                work,
                std::future::pending(),
                Arc::new(AtomicBool::new(false)),
            )));
        }
        timeout(Duration::from_secs(10), async {
            while starts.load(Ordering::SeqCst) == 0 {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        let holder = api
            .get(NAME)
            .await?
            .spec
            .and_then(|s| s.holder_identity)
            .ok_or_else(|| anyhow::anyhow!("missing holder"))?;
        let leader = usize::from(holder == "two");
        tasks[leader].abort();
        timeout(Duration::from_secs(25), async {
            while starts.load(Ordering::SeqCst) < 2 {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert!(!overlap.load(Ordering::SeqCst));
        for task in tasks {
            task.abort();
        }
        namespaces.delete(&name, &Default::default()).await?;
        Ok(())
    }
}
