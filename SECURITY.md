# Security

Omna's whole job is to keep data from leaving your machine. If that is ever not true, we want to
know before your users do.

## Reporting a vulnerability

**Email: gaurjin@gmail.com** with `[SECURITY]` in the subject line, or use GitHub's
[private vulnerability reporting](https://github.com/gaurjin/omna-plugin/security/advisories/new).

Please do **not** open a public issue for a security problem.

What helps:

- What you found, and what an attacker could do with it.
- The smallest set of steps that shows it.
- The version (`omna version`) and your OS.
- Whether you think it is already being exploited.

**Please do not include real secrets or real personal data in a report.** If you found a masking
failure, a made-up value that reproduces it is worth more to us than a real one — and `omna mask`
will let you check a fake value without sending anything anywhere.

### What to expect

| | |
|---|---|
| First reply | within 3 working days |
| Assessment | within 10 working days |
| Fix for a confirmed high-severity issue | as fast as we can, and we will tell you the date |
| Credit | your name in the release notes, unless you'd rather stay anonymous |

This is a small project, so those are honest targets from a small team, not a contractual SLA.

## What counts as a vulnerability here

**Yes, please report:**

- Any way to make Omna send unmasked data to a provider.
- Any way to read `~/.omna/registry.json` without the Keychain key.
- Any way to make the proxy forward a request it should have refused.
- Any path that writes a real value into a log, a receipt, a crash report, or anywhere on disk
  outside the encrypted registry.
- Any way for a web page, or another user on the same machine, to use the proxy or read its state.
- Anything that would let a swapped detection model go unnoticed.

**Known and documented, not a vulnerability:**

- **Detection misses.** No PII detector catches everything. A missed name in prose is a quality bug
  — please still report it, as a normal issue, with a fake example. It is not a security hole.
- **Anything already running as you on your own machine.** A process with your user rights can read
  your Keychain-backed key, your files, and your memory. Nothing a local tool does can prevent
  that, and we do not claim otherwise.
- **Pinned apps.** An app that checks certificate fingerprints itself is *refused*, never forwarded
  unmasked. That is the design working.
- **The PAC-file gap.** If the daemon dies, a browser that has not yet loaded the proxy settings
  falls back to a direct connection. This is documented in the README's "Honest limits" and is a
  real limitation, not a secret one.
- **Thinking blocks.** Model reasoning is passed through untouched in both directions because the
  API requires it.

## Scope

In scope: this repository, the `omna` command, and the local proxy it runs.

Out of scope: the AI providers themselves, `uv`, `mitmproxy`, and other dependencies — please report
those upstream, though we would still like to hear about it so we can pin or patch.

## How we try to earn the trust

- **Nothing is sent to Omna.** The only outbound connection is your own request to your own
  provider. A test reads our crash-reporting module's own source code and fails the build if
  networking is ever added to it.
- **Crash reports are off by default**, masked by the engine before they are written to disk, and
  sent only if you say yes when asked.
- **The registry is encrypted at rest** (AES-256-GCM, key in the macOS Keychain).
- **The detection model is verified** against a pinned SHA-256 before it is ever loaded.
- **Receipts are hash-chained**, so `omna log --verify` tells you whether anything was altered.
- **The local dashboard requires a token** from an owner-only file.

## Supply chain

- Releases are tagged and published from this repository.
- The masking engine ships as a compiled wheel (`omna-pii-mask`) built from a private kernel; its
  release artefacts are built in CI, not on a laptop.
- Dependencies are pinned in `uv.lock`.
- See `docs/SBOM.md` for the component inventory and how to regenerate it.
