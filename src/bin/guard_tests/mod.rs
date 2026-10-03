//! Runs the actual guard rules inside a disposable network namespace.
use super::*;

#[tokio::test]
#[ignore = "requires VPC_GUARD_KERNEL_TEST=1 and an isolated privileged Linux network namespace"]
async fn kernel_drops_fallback_and_expires_local_gateway_permits() -> Result<()> {
    ensure!(
        std::env::var("VPC_GUARD_KERNEL_TEST").as_deref() == Ok("1"),
        "explicit isolated test environment required"
    );
    // The harness unshares the outer network namespace; refuse a normal host.
    let links = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .await?;
    ensure!(
        String::from_utf8_lossy(&links.stdout).lines().count() == 1,
        "expected an empty network namespace with loopback only"
    );
    let client = format!("vpc-client-{}", std::process::id());
    let server = format!("vpc-server-{}", std::process::id());
    for ns in [&client, &server] {
        command("ip", &["netns", "add", ns]).await?;
    }
    let result: Result<()> = async {
        command(
            "ip",
            &[
                "link", "add", "source", "type", "veth", "peer", "name", "client0",
            ],
        )
        .await?;
        command("ip", &["link", "set", "client0", "netns", &client]).await?;
        command("ip", &["addr", "add", "10.66.0.1/24", "dev", "source"]).await?;
        command("ip", &["link", "set", "source", "up"]).await?;
        command(
            "ip",
            &[
                "-n",
                &client,
                "addr",
                "add",
                "10.66.0.2/24",
                "dev",
                "client0",
            ],
        )
        .await?;
        command("ip", &["-n", &client, "link", "set", "client0", "up"]).await?;
        command(
            "ip",
            &["-n", &client, "route", "add", "default", "via", "10.66.0.1"],
        )
        .await?;
        command(
            "ip",
            &[
                "link", "add", "outbound", "type", "veth", "peer", "name", "server0",
            ],
        )
        .await?;
        command("ip", &["link", "set", "server0", "netns", &server]).await?;
        command("ip", &["addr", "add", "203.0.113.1/24", "dev", "outbound"]).await?;
        command("ip", &["link", "set", "outbound", "up"]).await?;
        command(
            "ip",
            &[
                "-n",
                &server,
                "addr",
                "add",
                "203.0.113.2/24",
                "dev",
                "server0",
            ],
        )
        .await?;
        command("ip", &["-n", &server, "link", "set", "server0", "up"]).await?;
        command(
            "ip",
            &[
                "-n",
                &server,
                "route",
                "add",
                "default",
                "via",
                "203.0.113.1",
            ],
        )
        .await?;
        command("sysctl", &["-w", "net.ipv4.ip_forward=1"]).await?;
        // Test-only private classification makes the documentation subnet the
        // isolated public destination. There is no interface to the Internet.
        install("iptables-nft", &BTreeSet::from(["10.0.0.0/8".into()])).await?;
        let probe = || async {
            Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    &client,
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "203.0.113.2",
                ])
                .output()
                .await
                .map(|o| o.status.success())
        };
        ensure!(probe().await?, "baseline route must work");
        let ips = BTreeSet::from(["10.66.0.2".into()]);
        set("HC-VPC-MANAGED", "hash:ip", &ips).await?;
        ensure!(!probe().await?, "fallback must be blocked");
        set("HC-VPC-LOCAL", "hash:ip", &ips).await?;
        ensure!(probe().await?, "healthy local gateway must pass");
        tokio::time::sleep(Duration::from_secs(11)).await;
        ensure!(
            !probe().await?,
            "dead guard must lose local gateway permission"
        );
        command("ip", &["link", "set", "outbound", "name", "egress.vxlan"]).await?;
        ensure!(probe().await?, "selected tunnel path must pass");
        // Reproduce kube-router's policy mark and Flannel's catch-all SNAT.
        // The gateway only accepts the original Pod source, never a tunnel IP.
        command(
            "iptables-nft",
            &[
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-j",
                "MARK",
                "--set-xmark",
                "0x20000/0x20000",
            ],
        )
        .await?;
        command(
            "iptables-nft",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.66.0.0/24",
                "-j",
                "MASQUERADE",
            ],
        )
        .await?;
        command(
            "ip",
            &[
                "netns",
                "exec",
                &server,
                "iptables-nft",
                "-A",
                "INPUT",
                "-p",
                "icmp",
                "!",
                "-s",
                "10.66.0.2",
                "-j",
                "DROP",
            ],
        )
        .await?;
        ensure!(
            probe().await?,
            "tunnel must preserve the Pod source despite CNI marks and masquerade"
        );
        set("HC-VPC-MANAGED", "hash:ip", &BTreeSet::new()).await?;
        ensure!(
            !probe().await?,
            "unmanaged traffic must retain normal CNI masquerade"
        );
        set("HC-VPC-MANAGED", "hash:ip", &ips).await?;
        ensure!(probe().await?, "managed source exemption must recover");
        // Restarting must not erase the managed set and permit fallback.
        command("ip", &["link", "set", "egress.vxlan", "name", "outbound"]).await?;
        install("iptables-nft", &BTreeSet::from(["10.0.0.0/8".into()])).await?;
        ensure!(!probe().await?, "guard restart must remain closed");
        Ok(())
    }
    .await;
    for ns in [&client, &server] {
        let _ = command("ip", &["netns", "delete", ns]).await;
    }
    result
}
