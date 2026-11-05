# Infrastructure

Terraform for the infrastructure the WithHuman engine runs on. The engine itself is deployed by
Argo CD with the Helm chart in `deploy/k8s/withhuman` and the values in `withhuman-gitops`.

The deployment stays portable across AWS, Azure and GCP: everything above the cluster (images, the
chart, Argo CD) is the same on each cloud, and each cloud has its own directory here that provides
the same things:

- a Kubernetes cluster whose nodes enforce NetworkPolicies
- a Neo4j that only the cluster's nodes reach
- a Redis-compatible store, given to the engine only as a URL
- a secret holding `neo4j-password` and `redis-url`, and one holding the Jev API key

```text
aws/
├── bootstrap/        S3 bucket for the Terraform state (once per account)
├── modules/neo4j/    Neo4j on EC2
└── staging/          staging in ap-northeast-2
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

5. Put `neo4j_http_url` and `neo4j_bolt_url` into `envs/staging/values.yaml` of withhuman-gitops.

Staging uses one NAT gateway and one Valkey node to keep costs down. Neo4j keeps its data on the
instance's root volume, snapshotted daily for seven days; destroying the stack deletes it.

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
