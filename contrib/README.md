# Integrations

| Path | What |
| --- | --- |
| `checkmk/hvpatch` | Checkmk local check (`/usr/lib/check_mk_agent/local/`): OK, WARN on reboot recommended or no livepatch, CRIT on failure or expiry, with metrics |
| `hooks/90-notify` | Hook that posts every load to a webhook (ntfy, Matrix, Slack, …) |
| `ansible/roles/hvpatch` | Installs and configures the agent |
| `ansible/rollout.yml` | One node at a time, canary group first, stops at the first unhealthy node |

Prometheus: the agent already writes `hvpatch.prom` for the node_exporter
textfile collector (`textfile_dir`), see `docs/architecture.md`.

Ansible example:

```yaml
# group_vars/hvpatch_nodes.yml
hvpatch_repository: https://klp.example.org
hvpatch_manifest_key: files/manifest.pub
hvpatch_ring: stable
hvpatch_settings:
  delay_hours: 24
```

```bash
ansible-playbook -i inventory site.yml          # applies roles/hvpatch
ansible-playbook -i inventory contrib/ansible/rollout.yml
```
