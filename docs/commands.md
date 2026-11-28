# Commands

| Command | What it does |
| --- | --- |
| `hvpatch setup` | Set repository, ring and trusted key, then run `check` |
| `hvpatch check` | Kernel config, ftrace, Secure Boot and MOK, keys, repository, tracing conflicts |
| `hvpatch status [--json]` | Active level, fixed CVEs, CVEs that still need a reboot |
| `hvpatch apply [--level N]` | Fetch, verify and load the livepatch for the running kernel |
| `hvpatch revert` | Disable and unload; hold until the next explicit `apply` |
| `hvpatch auto enable\|disable` | Hourly timer for new levels (off by default) |
| `hvpatch mok enroll` | Enroll the module certificate for Secure Boot |

`status` with a fix that needs a reboot (example output):

```console
$ hvpatch status
kernel:        7.3.5-1-pve
ring:          stable
state:         active
livepatch:     klp_hvp_7_3_5_1_p3 (level 3)
manifest:      level 3, signed by repository, built 2026-11-23 09:00 (0 days ago), expires 2026-12-23
fixed live:    CVE-2026-XXXXX, CVE-2026-YYYYY
NOT covered:   CVE-2026-ZZZZZ (struct change), fixed in 7.3.6-1-pve
reboot:        REQUIRED
               - not fixable by livepatch: CVE-2026-ZZZZZ
```

After a reboot into the same kernel, the boot unit reloads the active level
from the local cache before guests start. After a reboot into a new kernel,
nothing old is loaded.

<details>
<summary>Exit codes for monitoring and Ansible</summary>

| `status` | Meaning |
| --- | --- |
| 0 | livepatch active, no known CVE needs a reboot |
| 10 | livepatch active, but a reboot is required |
| 11 | no livepatch active (state `pending` right after a reboot, until the boot unit has reloaded it) |
| 12 | manifest expired: no further patches are coming |
| 20 | last operation failed, or an operation or transition in progress |

| `apply` / `boot` / `revert` | Meaning |
| --- | --- |
| 0 | applied, already active, nothing published, or on hold |
| 2 | failed and backed out |
| 3 | rejected by verification or policy; nothing loaded |
| 4 | precondition failed (transition running, forced leftover, foreign patch) |

systemd shows these codes with LSB names (`status=3/NOTIMPLEMENTED` for a
rejected manifest); only the meanings above apply.

Metrics: `/var/lib/prometheus/node-exporter/hvpatch.prom`
(`hvpatch_active_level`, `hvpatch_reboot_required`, `hvpatch_failed`, ...),
written whenever that directory exists (it does once the node_exporter
textfile collector is set up). Set `textfile_dir` to change or `""` to turn
it off.
</details>
