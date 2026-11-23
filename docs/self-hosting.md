# Running your own pipeline

Recommended for fleets: you only trust the catalog you review and your own
build host.

## Keys

```
# Manifest key (minisign-compatible). Prefer `minisign -G` on an offline
# machine; the agent accepts both.
pve-klp-tool keygen --secret manifest.secret --public manifest.pub

# Module signing certificate (X.509), like for DKMS modules.
openssl req -new -x509 -newkey rsa:4096 -sha512 -days 3650 -nodes \
  -subj "/CN=pve-klp module signing/" \
  -keyout module.priv -outform DER -out module-cert.der
```

On every node:

```
install -m 0644 manifest.pub /etc/pve-klp/trusted.d/own.pub
install -m 0644 module-cert.der /etc/pve-klp/module-cert.der
pve-klp mok enroll   # only with Secure Boot; confirm at the console on next boot
```

## Build

```
podman build -t pve-klp-builder -f builder/Containerfile .
podman run --rm -v $PWD:/work -e MODULE_KEY=/work/keys/module.priv \
  -e MODULE_CERT=/work/keys/module-cert.der pve-klp-builder \
  /opt/pve-klp/builder/build.sh 7.3.5-1-pve 1 /work/build/7.3.5-1-pve
```

Then run the QEMU stage and sign on the signing host:

```
MANIFEST_KEY=manifest.secret builder/sign-manifest.sh build/7.3.5-1-pve/out /srv/klp canary
```

Serve `/srv/klp` over HTTPS and set `repository = "https://…"` in
`/etc/pve-klp/pve-klp.toml`.

## Rollout

The agent only knows its ring. The fleet order comes from your configuration
management: canary node first, then one node per cluster, then the rest,
each with a waiting time. Stop at the first `pve-klp apply` exit code other
than 0. Never patch all nodes of a cluster at once.
