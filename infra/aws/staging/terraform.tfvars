kubernetes_version = "1.34"

# Replace with the office's public IP and the CI runners' range before applying.
api_allowed_cidrs = ["125.240.193.196/32"]

# Replace with the team's address for certificate expiry notices.
acme_email = "janghongseo@naver.com"

# The account is on the AWS Free Tier plan, which refuses to launch instance types that are
# not free-tier eligible. m7i-flex.large matches m7i.large's 2 vCPU / 8 GiB and is eligible;
# its CPU is burstable, which staging can absorb.
node_instance_types = ["m7i-flex.large"]

# Same Free Tier limit as the nodes: no eligible type carries 16 GiB, so Neo4j gets the 8 GiB
# m7i-flex.large. Neo4j runs in Docker without a memory limit, so the kernel's OOM killer is the
# only guard — heap and page cache are sized to leave the host real headroom.
#   8.0 GiB total - 2g heap - 3g page cache - ~0.5g JVM off-heap = ~2.5 GiB for AL2023 and Docker
neo4j_instance_type  = "m7i-flex.large"
neo4j_heap_size      = "2g"
neo4j_pagecache_size = "3g"
