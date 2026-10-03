# HeteroCloud VPC

Flashサービスをプライベートネットワークに接続するHeteroCloudプロバイダーです。HeteroCloud API / CLIで作成・更新・削除し、コンソールからも管理できます。

- 同じ組織・プロジェクト・リージョンのFlashだけを接続できます。
- VPC内の新しい接続は既定で拒否します。接続元・接続先のサービスまたはセキュリティグループと、TCP / UDPポートを指定して許可します。応答通信はステートフルに許可します。
- 内部DNSは `名前.hc-vpc-<VPC UUIDのハイフンを除いた値>.svc.<clusterDomain>`。宛先ポートはコンテナポートです。内部向けのサービスは公開DNS・ロードバランサー・NodePortを作成しません。
- NATは既定で無効です。有効にするとFlashの送信許可・拒否CIDRを適用して公開IPv4宛先へ接続できます。VPC内の通信ルールとは独立しています。
- 利用中のVPCやセキュリティグループは削除できません。内部DNS名はVPC内で一意です。

## 作成

`HETEROCLOUD_ENDPOINT` と `HETEROCLOUD_ORGANIZATION_ID` を自分の環境に設定し、CLIでログインしてから実行します。公開ドメインはコードに固定していません。

```sh
heterocloud vpc create --file vpc.json
heterocloud flash create --file child.json
heterocloud vpc get VPC_ID
```

`vpc.json`:

```json
{
  "project_id": "PROJECT_UUID",
  "name": "coder-workspaces",
  "spec": {
    "region": "REGION",
    "nat": {"enabled": true},
    "security_groups": ["coder", "workspaces"],
    "rules": [{
      "source": {"type": "security_group", "name": "coder"},
      "destination": {"type": "security_group", "name": "workspaces"},
      "protocol": "tcp",
      "port": 22
    }]
  }
}
```

Flashの `spec` に次を追加します。

```json
{
  "network": {
    "vpc_id": "VPC_UUID",
    "security_groups": ["workspaces"],
    "private_name": "workspace-one"
  },
  "exposure": {"type": "internal", "traffic_mode": "forwarded"},
  "ports": [{"name": "ssh", "protocol": "tcp", "container_port": 22}]
}
```

親のCoderサービスは `coder` グループへ接続します。子サービスはAPI / CLIから作成します。DockerソケットやKubernetes資格情報は渡しません。親専用のサービスアカウントを作り、Flash作成・取得・更新・削除と、必要なVPCグループへの `vpc:AttachSecurityGroup` をIAMで許可してください。APIキーはSecret Managerに登録して親のFlash編集画面から環境変数として接続します。子に資格情報が自動で引き継がれることはありません。

APIコレクションは `/api/v1/organizations/{organization_id}/vpc/networks`。POSTが作成、GETが一覧、`/{id}` のGET / PUT / DELETEが取得・更新・削除です。更新はspec全体の置き換えで、202後にreadyになるまで取得を繰り返します。CLIは既定でreadyまで待ちます。

IAMアクションは `vpc:ListNetworks`、`vpc:CreateNetwork`、`vpc:GetNetwork`、`vpc:UpdateNetwork`、`vpc:DeleteNetwork`、`vpc:AttachSecurityGroup`。リソースは `hc:org:<org>:vpc/network/<id>`、グループへの接続は末尾 `/security-group/<group>` です。Flashの作成権限は組織単位です。特定サービスIDの操作権限は既存IAMリソースで絞れます。

## 構成と境界

プロバイダーAPIは60秒以内のEd25519署名付きHeteroCloudコマンドだけを受け付けます。署名の組織・プロジェクト・サービスID・世代を照合し、同一世代の変更と古い世代の上書きを拒否します。Kubernetesへ署名秘密鍵を渡しません。

コントローラーは `VpcNetwork` と `FlashService` からNetworkPolicy、内部Service / DNS、EgressGateway / EgressPolicyを生成します。FlannelのPodアドレスは変更せず、VPCの分離をNetworkPolicyで実現します。独自CIDRや重複CIDR、IPv6 NATを提供する実装ではありません。

NATは [EgressGateway v0.6.9](https://github.com/spidernet-io/egressgateway/tree/v0.6.9) のIPv4 / iptablesデータプレーンを使用します。ゲートウェイ間のトンネルはHeteroNetインターフェースを使用します。ノードの外向きアドレスでSNATするため、専用固定EIPではなく、ゲートウェイ切り替え時に送信元IPや既存接続が変わる場合があります。

ノードのNAT guardがVPC Podの通常経路への迂回を拒否します。指定されたゲートウェイの出口か、EgressGatewayトンネルだけを通します。制御情報を取得できなくなるとローカル出口を停止します。Flashのinitコンテナはguardの準備を待ちます。テナントコンテナにはNET_ADMIN、hostNetwork、ホストのDockerソケットを付与しません。

接続ルールの変更は非同期で反映されます。ステートフルなNetworkPolicyのため、許可削除は新しい接続に適用され、既に確立した接続を即座に切断する機能ではありません。NAT無効化はguardとegressポリシーの両方で制御します。DNS名自体は秘密情報ではなく、アクセス制御は宛先の通信ポリシーで行います。

デフォルト上限: 組織あたり16 VPC、VPCあたり32グループ / 128ルール、Flashあたり8グループ。KubernetesおよびHeteroCloud管理者は信頼境界の内側です。

## 運用

Helm: `deploy/helm/heterocloud-vpc`。EgressGatewayのCRD・エージェントとkube-router NetworkPolicyエンジンを先に展開してください。IP masqueradeだけではVPCの分離は成立しません。ガードはFlashを配置する全Linuxノードに必要です。専用コントロールプレーンノードにはアプリケーションを配置しません。

`providerPublicKeysJson`、`gatewaySelector`、`protectedCidrs`、`flashNamespace`、`clusterDomain`、Flash側のguardアドレスを環境に合わせて設定します。HeteroCloud worker / APIには `HETEROCLOUD_VPC_ENDPOINT` を設定します。プロバイダーのAPIを公開インターネットへ公開する必要はありません。

```sh
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo run --locked --bin vpc-crdgen > deploy/helm/heterocloud-vpc/crds/vpcnetworks.yaml
helm lint --strict deploy/helm/heterocloud-vpc
```
