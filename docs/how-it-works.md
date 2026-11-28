# How it works

```mermaid
flowchart LR
  subgraph build["Build side (CI)"]
    C["catalog/<br/>reviewed CVE fixes"] --> B["klp-build<br/>against the exact<br/>Proxmox source"]
    S["shipped kernel<br/>config, System.map,<br/>Module.symvers"] --> G
    B --> G["Gate A<br/>module fits the<br/>shipped kernel"]
    G --> Q["QEMU test<br/>load, transition,<br/>unload"]
    Q --> SIG["sign module<br/>and manifest"]
  end
  SIG --> R[("static HTTPS<br/>repository")]
  subgraph node["Every PVE node"]
    A["hvpatch apply"] --> V["verify signature,<br/>build-id, hash"]
    V --> L["load, watch<br/>transition"]
    L --> P["post-checks:<br/>kernel log, taint,<br/>functions, hooks"]
  end
  R --> A
```

- **One cumulative module per kernel.** It contains all fixes and replaces
  its predecessor atomically. At most one livepatch is active per node.
- **Release rings** `canary` → `early` → `stable` are separately signed
  manifests. A maintainer promotes a level explicitly; nothing moves on a
  timer.
- **The build is pinned to the shipped kernel.** The shipped config is
  copied into the tree and compared byte for byte after `make olddefconfig`.
  Any compiler, linker, pahole or rustc difference aborts the build.

Details: [docs/architecture.md](architecture.md).
