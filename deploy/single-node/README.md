# Single-node deployment

This profile runs the complete engine, Neo4j and Redis on one Docker host. It pulls the immutable
commit-SHA images published by the Service Images workflow instead of building the Rust workspace.

## Local Docker host

Copy `.env.example` to `.env`, fill the secrets and choose a published full commit SHA, then run:

```sh
docker compose --env-file deploy/single-node/.env \
  --file deploy/single-node/compose.yaml up --detach --wait
```

The default binds the gateway to `127.0.0.1:3000`. Do not expose its plain HTTP port directly to
the internet. Stop the stack without deleting its Neo4j and Redis volumes with `docker compose`
`down`; adding `--volumes` deletes the stored data.

## AWS personal instance

`infra/aws/single-node` creates the VPC, EC2 host, Secrets Manager secrets, daily EBS snapshots,
an HTTPS Application Load Balancer, ACM certificate and Route 53 record. The host has no SSH port;
use Session Manager. Its systemd timer polls `source_ref`, verifies all three service images exist,
and converges Compose. A failed update attempts to restore the previous commit.

After `terraform apply`, set the Jev key printed by the `jev_secret_arn` output:

```sh
aws secretsmanager put-secret-value --secret-id "$(terraform output -raw jev_secret_arn)" \
  --secret-string '<jev-api-key>'
aws ssm send-command --instance-ids "$(terraform output -raw instance_id)" \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["systemctl restart withhuman.service"]'
```

The generated Neo4j password is intentionally stable. Rotating it requires changing the password
inside Neo4j before replacing the Secrets Manager value.
