#!/bin/bash
# Runs once, on the instance's first boot. NEO4J_AUTH only takes effect on an empty database.
set -euo pipefail

dnf install -y docker jq
systemctl enable --now docker

password=$(aws secretsmanager get-secret-value --region "${region}" --secret-id "${secret_arn}" \
  --query SecretString --output text | jq -r '.["${password_key}"]')

mkdir -p /var/lib/neo4j/data /var/lib/neo4j/logs
chown -R 7474:7474 /var/lib/neo4j

docker run --detach --name neo4j --restart unless-stopped \
  --publish 7474:7474 --publish 7687:7687 \
  --volume /var/lib/neo4j/data:/data --volume /var/lib/neo4j/logs:/logs \
  --env NEO4J_AUTH="neo4j/$password" \
  --env NEO4J_server_memory_heap_initial__size=${heap_size} \
  --env NEO4J_server_memory_heap_max__size=${heap_size} \
  --env NEO4J_server_memory_pagecache_size=${pagecache_size} \
  "${neo4j_image}"
