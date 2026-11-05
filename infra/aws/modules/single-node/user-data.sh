#!/bin/bash
# Runs once, on the instance's first boot. Everything after this is withhuman-apply's job: it
# resolves the source ref, reads the secrets and converges Compose, on boot and on the timer.
set -euo pipefail

dnf install -y docker git jq

# AL2023 packages the engine but not the Compose plugin, so the release binary is installed by hand.
install -d /usr/local/lib/docker/cli-plugins
curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-compose \
  "https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-x86_64"
chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose

systemctl enable --now docker

install -d -m 0755 /opt/withhuman
install -d -m 0700 /etc/withhuman

# A shallow clone would not hold the tags and branches withhuman-apply resolves against.
git clone "${repository_url}" /opt/withhuman/core
git -C /opt/withhuman/core -c advice.detachedHead=false checkout --force "${source_ref}"

# Terraform owns this file; withhuman-apply reads it and never writes it.
cat > /etc/withhuman/base.env <<'BASE_ENV'
# Written by Terraform (infra/aws/modules/single-node) and read by withhuman-apply, which sources
# it, adds the secrets and the resolved image tag to its own environment, and hands that to Compose.
# Secrets are never written to disk, so this file holds nothing sensitive.
${base_env}
BASE_ENV
chmod 0600 /etc/withhuman/base.env

install -m 0755 /opt/withhuman/core/deploy/single-node/withhuman-apply /usr/local/bin/withhuman-apply
for unit in withhuman.service withhuman-update.service withhuman-update.timer; do
  install -m 0644 "/opt/withhuman/core/deploy/single-node/$unit" "/etc/systemd/system/$unit"
done

install -d /etc/systemd/system/withhuman-update.timer.d
cat > /etc/systemd/system/withhuman-update.timer.d/schedule.conf <<'SCHEDULE'
[Timer]
# Replaces the unit's default rather than adding to it.
OnCalendar=
OnCalendar=${update_schedule}
SCHEDULE

systemctl daemon-reload
systemctl enable --now withhuman-update.timer

# The first run fails while the Jev key is unset, which is the expected state of a fresh deployment.
# The timer retries, so the host recovers on its own once the secret holds a value.
if ! systemctl enable --now withhuman.service; then
  echo "withhuman.service did not come up on the first boot. Read why with:" >&2
  echo "  journalctl -u withhuman.service -n 50" >&2
  echo "A missing Jev key is the usual cause; set it and run: systemctl start withhuman.service" >&2
fi
