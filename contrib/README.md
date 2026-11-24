# Integrations

| Path | What |
| --- | --- |
| `checkmk/hvpatch` | Checkmk local check (`/usr/lib/check_mk_agent/local/`): OK, WARN on reboot recommended or no livepatch, CRIT on failure or expiry, with metrics |
| `hooks/90-notify` | Hook that posts every load to a webhook (ntfy, Matrix, Slack, …) |
| `ansible/roles/hvpatch` | Installs and configures the agent |
| `ansible/rollout.yml` | One node at a time, canary group first, stops at the first unhealthy node |
| `prometheus/hvpatch.rules.yml` | Alerting rules: failed apply, stuck transition, interrupted operation, quarantine, stale metrics, expiry |
| `demo/demo.sh` | Terminal demo for recordings (test nodes only) |

Prometheus: the agent writes `hvpatch.prom` for the node_exporter textfile
collector (`textfile_dir`) when `apply`, `boot`, `revert` or `status`
finishes, not during a transition. On canary nodes, run `hvpatch status`
every few minutes (timer or cron) so the values stay current.

| Signal | Meaning | Operator? |
| --- | --- | --- |
| `hvpatch_failed == 1` | last operation failed; the agent backed out to the previous level | yes, read `hvpatch status` (last error) |
| `hvpatch_transition_in_progress == 1` for minutes | the reversal of a stalled transition stalled too; the agent stopped | yes, never force |
| `hvpatch_info{state=~"fetched\|verified\|loading"}` for minutes | an operation was interrupted; the level gets quarantined | look why (crash, kill, reboot) |
| `hvpatch_quarantined > 0` | a level is not loaded again automatically | decide: `hvpatch apply` or wait for a fixed level |
| exit code of `hvpatch status` | 0 ok, 10 reboot required, 11 not active, 12 expired, 20 failed or in progress | for scripts and Checkmk |

Validate the rules with `promtool check rules contrib/prometheus/hvpatch.rules.yml`.

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
