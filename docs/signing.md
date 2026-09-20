# How to check that the Omna you installed is the Omna we published

Three distribution routes, three different guarantees. Here is what each one
actually gives you, without overstating it.

## 1. Homebrew cask — signed by Apple's notary service

```sh
brew tap gaurjin/omna https://github.com/gaurjin/omna-plugin
brew install --cask omna
```

This is the strongest route, and the one to use if you care about this.

The binary is code-signed with our Apple **Developer ID** and submitted to
Apple for **notarization**. Apple scans it and issues a ticket. Your Mac checks
that ticket before it runs — that is why the download does not get the
"unidentified developer" block.

Check it yourself at any time:

```sh
codesign --verify --strict --verbose=2 $(readlink -f $(which omna))
codesign -dv --verbose=4 $(readlink -f $(which omna)) 2>&1 | grep Authority
```

You should see `Authority=Developer ID Application: Gaurav Jindal (HGVZ7MLM7N)`
and `Authority=Apple Root CA`. Anything else means it is not our build.

Homebrew also checks the download's SHA-256 against the one in the cask before
it installs anything, so a tampered release asset fails there first.

**Note on `spctl`:** running `spctl --assess --type execute` on `omna` reports
*"the code is valid but does not seem to be an app"*. That is expected — `omna`
is a command-line tool, not an `.app` bundle, and `spctl`'s app assessment does
not apply. The `codesign --verify` above is the correct check. For the same
reason the notarization ticket cannot be *stapled* into a bare CLI binary;
Gatekeeper verifies it online instead, which we tested by setting the
quarantine attribute on a fresh download and running it.

## 2. GitHub release assets — SHA-256 checksums

Every release carries `SHA256SUMS.txt`. Verify a download before using it:

```sh
curl -fsSLO https://github.com/gaurjin/omna-plugin/releases/download/v0.6.0/omna-0.6.0-macos-arm64.zip
curl -fsSLO https://github.com/gaurjin/omna-plugin/releases/download/v0.6.0/SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

## 3. `uv tool install` from git — signed commits and tags

```sh
uv tool install --python 3.12 git+https://github.com/gaurjin/omna-plugin@v0.6.0
```

This installs from a **tag**, not a moving branch, so you get exactly the tree
that tag points at. Check the tag resolves to the commit you expect:

```sh
git ls-remote --tags https://github.com/gaurjin/omna-plugin v0.6.0
```

**Honest limit:** this route builds from source on your machine and pulls
dependencies from PyPI, so its integrity is only as good as PyPI's. The
Homebrew cask route does not have that exposure — everything is baked into one
notarized artefact.

## What is *not* signed, and why

**The masking engine wheel (`omna-pii-mask`) is not separately signed.** It is
published to PyPI from CI, and PyPI records its own hashes, but we do not
attach a detached signature to it. If you want a cryptographically verified
engine today, use the Homebrew cask — the engine is inside the notarized
bundle, so Apple's signature covers it.

**We do not do reproducible builds.** For an honest reason rather than a
missing to-do: the masking kernel is closed source. A reproducible build is a
promise that *you* can rebuild the artefact from source and get identical
bytes. You cannot build our kernel, so there is nothing for you to reproduce.
Claiming reproducible builds while shipping a closed binary would be
meaningless. Notarization is the guarantee that actually applies here: not
"you can rebuild this", but "Apple confirms this came from us and has not been
altered since".

## Reporting something that looks wrong

If a signature check fails on something you downloaded from us, treat it as a
security report: see [SECURITY.md](../SECURITY.md).
