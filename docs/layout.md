# Repository layout

| Path | Content |
| --- | --- |
| `crates/hvpatch` | node agent (Rust, single binary) |
| `crates/hvpatch-tool` | build tool: catalog, Gate A, manifests, signing |
| `crates/klp-core` | shared manifest, signature, policy and ELF code |
| `catalog/` | reviewed CVE entries and patches |
| `builder/` | build container and pipeline scripts |
| `packaging/`, `debian/` | systemd units, Debian packaging |

Build: `make test`, `make static` (static musl binary), `make deb`. Rust 1.88+.
