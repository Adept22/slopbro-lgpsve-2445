# SlopBro — LGPSVE-2445 TOCTOU edition

This repository is based on a direct clone of
[`throwaway96/slopbro`](https://github.com/throwaway96/slopbro), upstream commit
`f76b717c7e7b537158bca9969a2675f847019c51`.

It preserves the original SlopBro mode and adds an experimental SSH-assisted
TOCTOU bypass for LG's realpath-based jsserver hardening. The additional mode
is enabled only with `--race-lgpsve2445`.

**This is the external-`wwwroot` edition.** The Python file contains no embedded
payload copies. The original web assets and every race-specific helper are real,
editable files under `wwwroot/`. Keep `slopbro.py` and `wwwroot/` together.

Use this code only on a device you own or are explicitly authorized to test.
It is research software without warranties.

## Repository layout

| Path | Purpose |
| --- | --- |
| `slopbro.py` | Original launcher plus race-mode orchestration |
| `wwwroot/index.html` | Unmodified upstream SlopBro browser payload |
| `wwwroot/main.js` | Unmodified upstream root entry point |
| `wwwroot/autoroot.sh` | Unmodified upstream rooting/persistence script |
| `wwwroot/package.json` | Unmodified upstream fake-service metadata |
| `wwwroot/race.html` | WAM page for prechecks, synchronized attempts, and statistics |
| `wwwroot/flipper.js` | Node.js atomic symlink flipper |
| `wwwroot/flipper.sh` | Shell fallback flipper; requires atomic `mv -fT` |
| `wwwroot/race-service.js` | Valid JavaScript template for the root-only payload |
| `tests/test_slopbro.py` | Upstream regression tests plus external-asset/race tests |
| `tools/package_single_file.py` | Upstream packager; not applicable to standalone race mode |

The four original `wwwroot` files come from the cloned upstream repository,
not from a reconstructed HTML or shell listing.

## Operating modes

### Original SlopBro

The original workflow remains available:

```bash
python3 slopbro.py --webos-version 7 192.168.88.31
```

It starts the normal HTTP server, pairs over SSAP, launches a suitable WAM app,
and serves `index.html`, `main.js`, `package.json`, and `autoroot.sh`.

The upstream options continue to work, including `--debug`,
`--curl-insecure`, `--fake-service-path`, `--no-fake-service-path`,
`--local-ip`, `--webos-version`, `--asset-source`, and `--test-server`.

In this directory edition, use the default `--asset-source auto` or select
`--asset-source dir`. No assets are pre-embedded in `slopbro.py`.

### LGPSVE-2445 race mode

The race mode uses Dev Mode SSH only to prepare files and run the flipper. It
does **not** require a modified helper IPK. The browser component is launched
through the same SSAP/WAM mechanism as upstream SlopBro.

Basic invocation:

```bash
python3 slopbro.py \
  --race-lgpsve2445 \
  --webos-version 7 \
  192.168.88.31
```

With an explicit SSH private key and debug output:

```bash
python3 slopbro.py \
  --race-lgpsve2445 \
  --webos-version 7 \
  --race-ssh-key /path/to/webos_key \
  --debug \
  192.168.88.31
```

If the PC advertises the wrong LAN address, add:

```bash
--local-ip <PC_LAN_IP>
```

Do not copy `slopbro.py` to another directory without `wwwroot/`; race mode
checks for its external assets before connecting to the TV.

## Requirements

### PC

- Python 3.8 or newer.
- The system OpenSSH client (`ssh`).
- Network access to the TV over SSAP and Dev Mode SSH.
- A LAN route that allows the TV to connect back to the PC's HTTP server.

### TV

- A working Dev Mode SSH account, normally `prisoner` on port `9922`.
- An SSH key already accepted by the TV. The launcher uses `BatchMode=yes`;
  interactive password entry is not supported.
- An SSAP pairing confirmation on the TV.
- An existing trusted service directory. The default is
  `/usr/palm/services/com.palm.service.devmode`.
- Internet access for the upstream Homebrew Channel download, or a local clean
  IPK supplied with `--hbchannel-ipk`.

Test SSH before running the exploit:

```bash
ssh -p 9922 prisoner@192.168.88.31 'id'
```

With a separate key:

```bash
ssh -i /path/to/webos_key -p 9922 prisoner@192.168.88.31 'id'
```

For a new SSH host key, the launcher accepts additional OpenSSH options:

```bash
--race-ssh-option StrictHostKeyChecking=accept-new
```

Repeat `--race-ssh-option` when more than one option is needed.

## Clean Homebrew Channel IPK

By default, the unmodified upstream `autoroot.sh` downloads the official
Homebrew Channel release. To avoid depending on Internet access from the TV,
supply an official, unmodified IPK:

```bash
python3 slopbro.py \
  --race-lgpsve2445 \
  --webos-version 7 \
  --hbchannel-ipk /path/to/org.webosbrew.hbchannel_0.7.3_all.ipk \
  192.168.88.31
```

Do not use an IPK into which an experimental service or flipper was previously
injected. IPK replacement was a helper-delivery technique in the manual PoC;
it is not part of this implementation.

## Race-mode options

| Option | Default | Meaning |
| --- | --- | --- |
| `--race-lgpsve2445` | off | Enable the SSH-assisted TOCTOU workflow |
| `--race-attempts <n>` | `1000` | Unique race pathnames per batch |
| `--race-batches <n>` | `1` | Fresh directories and independent batches |
| `--race-timeout <seconds>` | `180` | Maximum duration of one race batch |
| `--autoroot-timeout <seconds>` | `300` | Maximum wait after root for `autoroot.sh` |
| `--race-ssh-user <user>` | `prisoner` | Dev Mode SSH user |
| `--race-ssh-port <port>` | `9922` | Dev Mode SSH port |
| `--race-ssh-key <path>` | OpenSSH defaults | Explicit private key |
| `--race-ssh-option <option>` | none | Extra OpenSSH `-o` option; repeatable |
| `--race-trusted <path>` | devmode service | Existing trusted service directory |
| `--race-app-id <id>` | trusted basename | appId used by generated payload metadata |
| `--hbchannel-ipk <path>` | none | Optional clean IPK to upload |
| `--race-keep-files` | off | Preserve the remote batch directory and logs |

Race mode cannot be combined with `--test-server`. Attempts, batches, and
timeouts must be positive.

For three independent batches:

```bash
python3 slopbro.py \
  --race-lgpsve2445 \
  --webos-version 7 \
  --race-attempts 1000 \
  --race-batches 3 \
  192.168.88.31
```

Each batch receives a new run ID, a new remote directory, new pathnames, and
new control files. There is no need to repeat a manually chosen pathname.

## How the race works

1. The launcher verifies that all required files exist in the real `wwwroot/`.
2. It validates the Dev Mode SSH connection.
3. It pairs with the TV over SSAP and chooses a compatible WAM target app.
4. For each batch, it creates `/tmp/slopbro-race-<run-id>/` as a non-sticky
   working directory.
5. It uploads `race-service.js` after expanding only its two path placeholders,
   generates matching `package.json` and `services.json`, and uploads the real
   `flipper.js`, `flipper.sh`, and `autoroot.sh` files.
6. The flipper preallocates `k3u0` through `k3uN`, initially pointing every link
   to the trusted service. `helper.ready` is written only after preallocation
   succeeds.
7. `race.html` checks the direct trusted path and a static symlink in the
   non-sticky directory. A failed precheck stops the batch before the race.
8. Attempt `N` calls jsserver with unique path `k3uN` and control token `k3cN`.
   The cgroup token write also tells the flipper when to advance.
9. The flipper atomically replaces the active link with a temporary symlink and
   `rename()`/`mv -fT`, alternating between trusted and payload targets.
10. A winning resolution sequence is trusted during path validation and payload
    during module loading.
11. The root branch writes `rooted.flag` and starts the autoroot wrapper once.
12. The PC waits for both the root-only marker and an `autoroot.sh` exit code,
    then stops the flipper and removes temporary files unless requested to keep
    them.

## Why these conditions matter

### Canonicalization and use are separate operations

The patched code validates `fs.realpathSync(path)`, but later uses the original
pathname for operations such as `chdir()` and module loading. Repeating realpath
validation does not bind the validated object to the consumed object. Atomic
symlink replacement can therefore change the resolution between operations.

### The links must not be directly in sticky `/tmp`

On the tested device, direct trusted paths worked, while symlinks to those same
paths directly in `/tmp` were rejected. Equivalent symlinks inside a separate
non-sticky directory worked. This is consistent with protected-symlink behavior;
the implementation therefore creates a dedicated working directory.

### Trusted and payload appIds must align

A mismatched payload appId can trigger `SetAppid: Application Id already has
been set`. By default, the generated metadata uses the basename of the trusted
service path. Override it with `--race-app-id` when necessary.

### Every attempt needs a fresh pathname

Reusing one pathname produced trusted responses without payload execution in
manual experiments, while fresh pathnames succeeded quickly. This strongly
suggests pathname-based caching in the module-loading path, although the exact
cache implementation was not source-verified. The launcher therefore never
reuses race pathnames within or across batches.

### `returnValue:true` is not proof of root

A trusted service can also produce a successful response. Success is recognized
only when the payload's `process.getuid() === 0` branch creates the root marker,
and autoroot success additionally requires exit code `0`.

## Successful result

Expected launcher messages include:

```text
ROOT CONFIRMED by root-only marker
rooting and autoroot completed successfully
```

The final JSON result contains:

```json
{
  "returnValue": true,
  "root": true,
  "autorootExitCode": 0
}
```

Follow any instructions printed by `autoroot.sh`. In particular, if it asks you
to remove the LG Dev Mode app before rebooting, follow that instruction to avoid
losing installed applications or persistence. If the TV is already rooted and
configured, do not rerun the exploit merely to reproduce this output.

## Diagnostics

### SSH fails

First make a plain `ssh ... 'id'` command work. Check the user, port, key, host
key, and Dev Mode session. SSH authentication and permission errors are not
empty exploit results and must be resolved before continuing.

### `precheck-direct-*`

The direct trusted service path did not load. Check `--race-trusted` and the
corresponding appId. The default trusted path is:

```text
/usr/palm/services/com.palm.service.devmode
```

### `precheck-link-*`

A static symlink in the non-sticky working directory was rejected. Do not move
the links directly into sticky `/tmp`; that layout was already rejected in the
manual experiments.

### `prealloc fatal`, `flip error`, or `EACCES`

The flipper could not create or replace links. Rerun diagnostics with:

```bash
--race-keep-files --debug
```

The launcher prints the remote directory and the tail of `helper.log` where
available.

### A batch finishes without root

Inspect the reported categories: `ok`, `chdir`, `launch`, `setappid`, `enoent`,
`module`, `other`, and `timeout`. Try multiple fresh batches with
`--race-batches 3`. Do not interpret a successful trusted response as root.

### Root is confirmed but autoroot fails

Do not automatically repeat the exploit. Preserve the files and inspect
`autoroot.log`. The root marker proves uid-0 payload execution, not successful
Homebrew Channel installation or persistence.

### The TV cannot reach the PC

Use `--local-ip <PC_LAN_IP>`, check firewall rules, and verify bidirectional LAN
connectivity. Original-mode `--test-server simple` can help diagnose ordinary
HTTP reachability, but it cannot be combined with race mode.

## Cleanup

By default, after each batch the launcher:

1. creates `stop.flag`;
2. terminates the recorded flipper PID;
3. closes the local race HTTP server; and
4. removes the batch's `/tmp/slopbro-race-<run-id>/` directory.

`--race-keep-files` preserves that directory for analysis.

Old manual experiments are outside the launcher's ownership and are not deleted
automatically. After saving useful logs, inspect and remove only the experimental
objects you created, such as `/tmp/k3*`, `/tmp/k4_*`, `/var/run/k3*`, old race
working directories, and their flipper processes. Do not delete clean Homebrew
Channel files, root persistence files, or unrelated system services. If an old
experiment modified an installed Homebrew service, reinstall an official clean
IPK rather than deleting the application indiscriminately.

## External-asset contract

Race mode deliberately bypasses the embedded-asset resolver. It reads these
files directly from the `wwwroot` directory beside `slopbro.py`:

```text
race.html
flipper.js
flipper.sh
race-service.js
autoroot.sh
```

`race-service.js` is syntactically valid JavaScript even before customization.
The launcher replaces the values of `__SLOPBRO_RACE_BASE__` and
`__SLOPBRO_AUTOROOT_WRAPPER__`, checks that each placeholder occurs exactly once,
and rejects any unexpanded placeholder.

The upstream single-file packaging tool is retained for original-mode
compatibility, but **a packed script is not a standalone race-mode package**.
Race mode still requires the external directory. For this edition, the normal
and recommended distribution is the complete directory or ZIP archive.

## Tests

Run all Python regression tests without connecting to a TV:

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers the upstream CLI and HTTP behavior plus:

- presence of real external race assets;
- empty embedded payload storage in this directory edition;
- fatal handling of missing external files;
- root-template expansion and escaping;
- proof that the race HTTP handler uses the filesystem rather than embedded data;
- race CLI forwarding and argument validation.

Additional release checks used for this edition:

- Python byte-compilation;
- `node --check` for standalone JavaScript and scripts extracted from both HTML
  pages;
- `sh -n` for `autoroot.sh` and `flipper.sh`;
- live local Node.js and shell flipper protocol tests;
- HTTP `/status` and `/report` tests;
- comparison of the four original assets with the cloned upstream files.

**Validation limitation:** the integrated race implementation still requires an
end-to-end run on a compatible TV. The underlying TOCTOU algorithm and its key
conditions were confirmed manually on the target device, but those manual
results must not be represented as an end-to-end test of this repository.

## Recommended vendor fix

Canonicalize the path once, validate the canonical result, and use only that
canonical path for every subsequent operation: `chdir()`, appId resolution,
module loading, and cache keys. Input-character filtering and additional
`realpathSync()` calls around the original pathname do not remove the race.

## Upstream status notice

The cloned upstream README states that SlopBro is not expected to work on webOS
10 and 11 firmware released since approximately 2026-10-10 because LG fixed the
underlying jsserver vulnerability there. This race mode addresses the earlier
realpath-hardening bypass researched on the target webOS 7 device; it does not
claim support for every webOS version or firmware.

## Credits and license

Original SlopBro and its four original `wwwroot` assets are by
[`throwaway96`](https://github.com/throwaway96). Upstream credits reference
`dangbei-overlay` from `dangbro` and the initial public jsserver disclosure in
`jsbro-autoroot`.

The repository remains licensed under the GNU Affero General Public License,
version 3 or (at your option) any later version. See `COPYING` for the full
license text. No warranty is provided.
