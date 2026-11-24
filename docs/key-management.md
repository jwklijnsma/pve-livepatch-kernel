# Key management

hvpatch uses two keys with different jobs. Keep them apart.

| Key | Signs | Where it lives | Who needs the public part |
| --- | --- | --- | --- |
| **Module key** (X.509, RSA 4096) | the `.ko` (kernel module signature) | build host, read-only in the signing container only | Secure Boot nodes: enrolled as MOK (`hvpatch mok enroll`) |
| **Manifest key** (Ed25519, minisign) | `manifest.json`, `revoked.json` | signing host, ideally offline | every node: `/etc/hvpatch/trusted.d/*.pub` |

The manifest key is the one that matters most: it decides what every node
loads. The module key alone gets nothing onto a node that checks manifests.

## Creating

```bash
# module key (build host)
openssl req -new -x509 -newkey rsa:4096 -sha512 -days 3650 -nodes \
  -subj "/CN=<org> hvpatch module signing/" \
  -keyout module.priv -outform DER -out module-cert.der

# manifest key (signing host, offline if possible)
minisign -G -p manifest.pub -s manifest.secret      # or: hvpatch-tool keygen
```

Store both outside the repository (`run.sh` takes `KEYS=`). Back up the
manifest secret key encrypted and offline; losing it means re-keying every
node.

## Using

- `builder/run.sh` mounts the module key read-only into the signing
  container only.
- `builder/publish.sh`, `promote.sh` and `revoke.sh` sign with
  `MANIFEST_KEY` (hvpatch-tool) or `MINISIGN_KEY` (the `minisign` tool).
  For an offline key, run them on the offline machine with a copy of the
  repository directory and copy the result back.
- Every signature carries a trusted comment (kernel, level, ring, QEMU
  result), shown by `minisign -V`.

## Rotating the manifest key

Nodes accept any key in `trusted.d`, so rotation needs no flag day:

1. Create the new key; copy `new.pub` into `/etc/hvpatch/trusted.d/` on
   every node (e.g. with an Ansible `copy` task), next to the old one.
2. Sign new manifests and revocation lists with the new key.
3. When all published manifests are signed with the new key (they expire
   within 30 days), remove the old public key from the nodes.

## Rotating the module key

1. Create the new key; on Secure Boot nodes enroll the new certificate
   (`hvpatch mok enroll`, confirm in MokManager at the next reboot).
2. Build new levels with the new key once the nodes have it.
3. Remove the old MOK later (`mokutil --delete`).

Levels signed with the old key keep loading as long as its MOK is
enrolled.

## If a key leaks

- **Manifest key:** remove its public key from all nodes immediately
  (Ansible), publish with a new key, and treat everything signed after the
  suspected leak as untrusted. A revocation list signed with a leaked key
  proves nothing.
- **Module key:** on Secure Boot nodes, delete its MOK; build and publish
  new levels with a new key. Nodes still verify manifests, so a leaked
  module key alone does not get code loaded through hvpatch.

## The project's keys

The project will publish its manifest public key in the repository and on
the release page, with its fingerprint (key id), when project builds are
published. Until then there are none: use your own (`docs/self-hosting.md`).
