# Contributing

Thanks for helping. This project loads code into hypervisor kernels, so the
rules are stricter than usual.

## Catalog entries (CVE fixes)

1. Open a pull request that adds `catalog/<CVE-ID>/meta.yaml` and the patch.
   The format is described in [catalog/README.md](catalog/README.md).
2. Name the upstream commit(s). CI compares the patch with upstream via
   `git patch-id`; any deviation needs a written `reason`.
3. Classify honestly: `livepatchable` only for function-only changes that
   klp-build builds and the tests pass. Everything else is `needs-manual`,
   `not-livepatchable` or `mitigation-only`, and users see "reboot required".
4. Two maintainer approvals are required. Commits must be signed.

A backport for a specific kernel is a separate patch file with its own review.

## Code

- Rust: `make lint test` must pass (`cargo fmt`, `clippy -D warnings`, tests).
- Shell: `shellcheck -x -S warning builder/*.sh`.
- Agent changes that touch loading, transitions or verification need a test
  in `crates/hvpatch/tests/agent.rs` against the emulated kernel.
- Keep the agent small and dependency-light. It runs as root on hypervisors.

## Commit messages

Imperative mood, a short subject line (`agent: reverse stalled transition`),
and a body that explains why.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
