# WithHuman Helm chart

Deploys Collector, Generator, Decision and AgentGateway. Use private PostgreSQL and Redis endpoints
reachable from the engine pods. Set `database-url` to the PostgreSQL connection string. The current
engine connects over the private network without TLS.

## Before installing

Create the Secret the chart reads:

```sh
kubectl create secret generic withhuman \
  --from-literal=database-url=... \
  --from-literal=jev-api-key=... \
  --from-literal=redis-url=redis://...
```

Each environment's values live in the `withhuman-gitops` repository, and Argo CD installs the chart
from there. To install by hand, pass the same values:

```sh
helm upgrade --install withhuman deploy/k8s/withhuman \
  -f <environment-values.yaml> \
  --set imageTag=<commit-sha>
```

`imageTag` is the full commit SHA of an image built by the Service Images workflow. For private
images, list a pull Secret in `imagePullSecrets`.

Scale a service with its `replicaCount`, or set its `autoscaling.enabled`. The services spend most
of a request waiting on PostgreSQL or Jev, so CPU can stay low under load: confirm a CPU target with a
load test before relying on it.
