# Infrastructure

Terraform for the shared-cluster deployment. The engine itself is deployed by Argo CD with the
Helm chart in `deploy/k8s/withhuman` and the values in `withhuman-gitops`.

Nothing here is needed for a personal deployment: that one is the root `compose.yaml` on a single
Docker host, with no cloud account involved. See the repository's README.

The deployment stays portable across AWS, Azure and GCP: everything above the cluster (images, the
chart, Argo CD) is the same on each cloud, and each cloud has its own directory here that provides
the same things:

- a Kubernetes cluster whose nodes enforce NetworkPolicies
- a private PostgreSQL endpoint provisioned separately and reachable from the cluster
- a Redis-compatible store, given to the engine only as a URL
- secrets for `database-url`, `redis-url` and the Jev API key

```text
aws/
├── bootstrap/        S3 bucket for the Terraform state (once per account)
└── staging/          shared EKS staging in ap-northeast-2
```

## AWS staging

Requires Terraform 1.10 or later and AWS credentials that can manage VPC, EKS, EC2, IAM, ElastiCache
and Secrets Manager.

1. Create the state bucket, once per account:

   ```sh
   cd infra/aws/bootstrap
   terraform init && terraform apply
   ```

2. Configure staging: copy `backend.hcl.example` to `backend.hcl` with the bucket from step 1, and
   set `api_allowed_cidrs` in `terraform.tfvars`. Check that `kubernetes_version` is still offered
   with `aws eks describe-cluster-versions`.

3. Review the plan, then apply:

   ```sh
   cd infra/aws/staging
   terraform init -backend-config=backend.hcl
   terraform plan -out staging.tfplan
   terraform apply staging.tfplan
   ```

4. Store the Jev API key, which Terraform never holds:

   ```sh
   aws secretsmanager put-secret-value --secret-id "$(terraform output -raw jev_secret_arn)" \
     --secret-string '<jev-api-key>'
   ```

5. Provision PostgreSQL on a private network reachable from the engine pods. Store its connection
   string in the secret named by `database_url_secret_arn`. Map it to `database-url` in the chart's
   `externalSecret.data` in withhuman-gitops before deploying the new engine images.

Staging uses one NAT gateway and one Valkey node. An existing legacy database VM is removed from
Terraform management without destruction, so it can be backed up and kept during cutover.

### Staging PostgreSQL cutover

Image publication continues on `main`. Staging image promotions require the
`STAGING_POSTGRES_READY=true` repository variable in `withhuman-core`. Leave it unset during
the first PostgreSQL deployment.

1. Prepare the private PostgreSQL endpoint and its `database-url` secret. Keep the existing
   Neo4j deployment and credentials available for rollback. If its sessions must be retained,
   pause graph writes and follow the export, import and verification steps in the
   [repository README](../README.md#upgrading-an-existing-neo4j-deployment).
2. In one `withhuman-gitops` change, pin the engine chart in `apps/staging.yaml` to the
   PostgreSQL release commit, set `imageTag` in `envs/staging/values.yaml` to that published
   image SHA, and map the `database-url` secret to the chart. Keep the Redis and Jev mappings.
3. After Argo CD syncs, check the engine's health and confirm a new session and decision are
   persisted. Set `STAGING_POSTGRES_READY=true` to resume automatic staging image promotions.

## Cluster add-ons

`modules/platform` installs what the engine needs on any cloud: Argo CD, Traefik for Ingress,
cert-manager with a Let's Encrypt issuer, and External Secrets with a ClusterSecretStore. It then
registers withhuman-gitops with Argo CD and applies this cluster's Applications from it. Each cloud
passes its load balancer annotations and External Secrets provider; on AWS that is an NLB and
Secrets Manager read through EKS Pod Identity.

Before Argo CD can read withhuman-gitops, store a read-only deploy key of it:

```sh
ssh-keygen -t ed25519 -N '' -C argocd-gitops -f argocd-gitops
# Add argocd-gitops.pub to withhuman-gitops as a read-only deploy key, then:
aws secretsmanager put-secret-value --secret-id "$(terraform output -raw gitops_deploy_key_secret_arn)" \
  --secret-string file://argocd-gitops
```

Argo CD is not exposed; reach it with `kubectl -n argocd port-forward svc/argocd-server 8080:443`.
Point the staging host's DNS record at the Traefik load balancer
(`kubectl -n traefik get svc traefik`); cert-manager then issues its certificate.

## Not yet covered

- TLS between the Collector and Valkey: the Collector's Redis client is built without TLS.
- Azure and GCP.
