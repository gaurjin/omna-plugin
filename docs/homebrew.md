# Homebrew — how we ship it, and why it is a cask

**Status: SHIPPED 2026-09-20 as a cask.** Backlog item #133, closed.

```sh
brew tap gaurjin/omna https://github.com/gaurjin/omna-plugin
brew install --cask omna
```

Verified end to end: `brew audit --cask --strict` exits 0, the install works on a clean machine,
the binary is signed with our Developer ID and notarized by Apple (submission
52da3f18-108a-4272-b642-20eaafc5e0d8, Accepted), and a quarantined download runs and masks.

The rest of this page is the reasoning, kept because the next person will otherwise re-derive it.

## Why we want it

Our published install line is:

```sh
curl -fsSL https://omna.dev/cli/install.sh | bash
```

That pattern is disliked by exactly the audience we sell to: it runs a script from the internet
before you have read it. Homebrew is not just convenience here — it is credibility with the
security-minded buyer. See "Installing without piping to a shell" in the README for what we ship
*today* to address that directly; Homebrew is the nicer version of the same goal.

## What Kiji does, and why we cannot copy it yet

Kiji ships:

```sh
brew install --cask dataiku/tap/kiji-privacy-proxy
```

Note **`--cask`**, and the tap `dataiku/tap` (the GitHub repo `dataiku/homebrew-tap`).

A *cask* installs a **prebuilt binary** — Homebrew just downloads their DMG and checks its hash.
It never builds anything. Kiji can do this because they ship a compiled, signed, notarized app.

A *formula* builds from source. That is the right shape for a Python CLI like ours, but it means
Homebrew must be able to resolve every dependency offline from declared `resource` blocks.

## The three real blockers

1. ~~**`omna-plugin` is not on PyPI.**~~ **RESOLVED 2026-09-20** — published, `omna-plugin` 0.6.0,
   a pure-Python `py3-none-any` wheel. Verified by installing it by name into a clean virtualenv
   outside the source tree. This blocker is gone; the remaining two stand.
2. **The engine wheel is binary-only.** `omna-pii-mask` publishes three architecture-specific
   wheels and **no sdist**. Homebrew's Python formula pattern (`virtualenv_install_with_resources`)
   expects source distributions it can build; an arch-specific binary wheel does not fit the
   one-formula-many-machines model cleanly. This is the hard blocker, and it is a *deliberate*
   property of the product (the kernel is closed-source), not an oversight.
3. ~~**A tap repo must exist.**~~ **SOLVED without a new repo.** Homebrew's *two-argument* tap form
   takes an explicit URL — their docs: "The two-argument form does not impose this naming convention
   because the full URL is explicit." So `Casks/omna.rb` lives in `gaurjin/omna-plugin` itself. The
   cost is two commands instead of one. The old assumption was that we needed a repo named
   `gaurjin/homebrew-omna`. The bare `brew install omna` (no tap prefix) requires acceptance into
   **homebrew-core**, which has notability requirements (roughly: a meaningful star/fork/watcher
   count, a stable release history, and active maintenance) that this project does not meet yet.
   So #133's literal wording — `brew install omna` — is not achievable today even with everything
   else solved; `brew install gaurjin/omna/omna` is.

## The two honest paths

**Path A — formula (source install).** Publish `omna-plugin` to PyPI, then resolve blocker 2.
`mitmproxy` alone pulls ~40 transitive dependencies, each needing a pinned `resource` block
(generate with `brew update-python-resources`), so the formula will be long but mechanical. The
binary-wheel question has to be answered first.

**Path B — cask (prebuilt, the Kiji shape).** Build a single self-contained binary (PyInstaller or
`uv`-based), sign and notarize it with the Apple Developer ID we already use for the Mac app, and
ship a cask that downloads it and checks the hash. This side-steps blocker 2 entirely because the
engine wheel is baked into the artifact, and it matches what our closest competitor actually does.

**We took Path B** (2026-09-20). It matched the product — it matches the product
(closed kernel, notarized Mac artifact already in the pipeline) and avoids arguing with Homebrew
about binary wheels. Path A fights the product's own architecture.

## Releasing a new version of the cask

```sh
bash scripts/build-cask.sh                 # build, sign, notarize, staple, zip
gh release upload vX.Y.Z dist/omna-X.Y.Z-macos-arm64.zip --clobber
# then update version + sha256 in Casks/omna.rb and commit
brew audit --cask --strict gaurjin/omna/omna
```

## Two gotchas worth remembering

**Stapling fails on a bare CLI binary** with `Error 73`, and `spctl --assess --type execute` reports
"the code is valid but does not seem to be an app". Both are expected — those checks are for `.app`
bundles. Gatekeeper verifies a CLI tool online instead. Prove it the way we did: set
`com.apple.quarantine` on the downloaded zip, unzip, run it.

**`brew uninstall --zap` cannot remove Keychain items.** It trashes `~/.omna` but leaves the
registry key and the receipts key behind, because a zap stanza only trashes files. That is why the
cask's caveat tells people to run `omna uninstall` FIRST.

## PyPI

`omna-plugin` was published to PyPI on 2026-09-20 (0.6.0, pure-Python `py3-none-any`), so
`uv tool install omna-plugin` and `pipx install omna-plugin` both work and the installer script
resolves by name. **Gotcha:** the first upload of a *new* package needs an **account-scoped** PyPI
token. A project-scoped token returns `403 Forbidden`, because it cannot create a package that does
not exist yet.
