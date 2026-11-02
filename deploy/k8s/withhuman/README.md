# WithHuman Helm chart

Deploys Collector, Generator, Decision and AgentGateway. Neo4j and Redis run outside the cluster.

## Before installing

Create the Secret the chart reads:

```sh
kubectl create secret generic withhuman \
  --from-literal=neo4j-password=... \
  --from-literal=jev-api-key=... \
  --from-literal=redis-url=redis://...
```

Set `neo4j.httpUrl`, `neo4j.boltUrl` and `ingress.host` in the environment's values file.

## Installing

```sh
helm upgrade --install withhuman deploy/k8s/withhuman \
  -f deploy/k8s/withhuman/values-staging.yaml \
  --set imageTag=<commit-sha>
```

`imageTag` is the full commit SHA of an image built by the Service Images workflow. For private
images, list a pull Secret in `imagePullSecrets`.

Scale a service with its `replicaCount`, or set its `autoscaling.enabled`. The services spend most
of a request waiting on Neo4j or Jev, so CPU can stay low under load: confirm a CPU target with a
load test before relying on it.
