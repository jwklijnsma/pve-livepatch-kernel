# Writing livepatchable fixes

Most kernel CVE fixes change the code of a few functions. Those are
`livepatchable`: the upstream patch goes into the catalog unchanged
(`lint --upstream` checks the patch-id), `klp-build` turns it into a
module, and Gate A checks that it replaces exactly the reviewed functions.

This guide is about the rest: fixes that need more than new function code.
They are `needs-manual` in the catalog until someone does the work below.

## When a plain patch is not enough

| Fix changes | Livepatch approach |
| --- | --- |
| Only function bodies | plain patch (`livepatchable`) |
| A struct gains a field | shadow variable instead of the field |
| Data must be converted or a setting flipped when the patch goes live | callbacks |
| A global initialised in `__init` code | callback that does the init at patch time |
| Struct layout of existing objects, `__init` paths that already ran, assembler, vDSO, `notrace` code | not livepatchable: reboot |

## Shadow variables

A livepatch cannot add a field to objects that already exist. A shadow
variable attaches extra data to an object by its address
(`include/linux/livepatch.h`):

```c
#include <linux/livepatch.h>

#define KLP_SHADOW_SK_FLAG 0x1   /* unique per catalog: register it below */

/* instead of sk->new_flag */
bool *flag = klp_shadow_get_or_alloc(sk, KLP_SHADOW_SK_FLAG, sizeof(*flag),
                                     GFP_ATOMIC, NULL, NULL);
```

Free it where the object dies (`klp_shadow_free()`), and in a post-unpatch
callback for everything left (`klp_shadow_free_all()`), or the memory leaks
when the patch is disabled.

## Callbacks

`klp-build` picks up callbacks declared in the patch with the macros from
`include/linux/livepatch_helpers.h`:

```c
#include <linux/livepatch_helpers.h>

static int pre_patch(struct klp_object *obj)    { /* may fail: no patching */ return 0; }
static void post_patch(struct klp_object *obj)  { /* runs after the transition */ }
static void pre_unpatch(struct klp_object *obj) { }
static void post_unpatch(struct klp_object *obj){ klp_shadow_free_all(KLP_SHADOW_SK_FLAG, NULL); }

KLP_PRE_PATCH_CALLBACK(pre_patch);
KLP_POST_PATCH_CALLBACK(post_patch);
KLP_PRE_UNPATCH_CALLBACK(pre_unpatch);
KLP_POST_UNPATCH_CALLBACK(post_unpatch);
```

Callbacks run per object (vmlinux, or a module when it is loaded).

## States: cumulative levels and atomic replace

Every level replaces the previous one atomically. If level 3 set up a
shadow variable and level 4 does not know it, level 4's code ignores it,
and nobody frees it. The kernel can check this (`struct klp_state`), but
`klp-build` does not declare states in the module yet (`init.c`: "TODO
patch->states"). So hvpatch does it from the manifests:

```yaml
# catalog/CVE-…/meta.yaml
states: [{id: 1, version: 1}]
```

- `resolve` collects the states of all included fixes into the manifest.
- The agent refuses a level that does not carry every state of the active
  level at the same or a higher version (before anything is loaded), and
  does not restore an older level that lacks one; it disables the patch
  instead, which runs the unpatch callbacks.
- Ids are unique across the catalog. Raise the version when the state's
  layout or meaning changes; a newer version must be able to take over an
  older one.

Since all levels are cumulative, a fix with states stays in every later
level of that kernel, so its state does too.

## Review and tests

`needs-manual` fixes need more review than plain ones:

- the reasoning why the livepatch is equivalent to the upstream fix, in the
  pull request;
- a reproducer (`tests/reproducer.sh`, exit 1 vulnerable, 0 fixed): the
  QEMU stage runs it before, with, after and again with the patch;
- patch/unpatch cycles under load in the QEMU stage (`CYCLES`), which
  exercise the callbacks and the cleanup.

Then change the class to `livepatchable` and list the functions as usual.

## Registered states

| id | Entry | Meaning |
| --- | --- | --- |
| – | – | none yet |
