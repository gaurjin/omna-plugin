# Homebrew (`brew install omna`) — status, and what it is actually blocked on

**Status: not shipped.** This page exists so the next person does not re-derive the problem.
Backlog item #133.

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

1. **`omna-plugin` is not on PyPI.** Verified 2026-09-20: `pypi.org/pypi/omna-plugin/json` returns
   404. (`omna-pii-mask` 0.2.6 and `omna` *are* published.) A formula can point at a GitHub release
   tarball instead, so this one is soft — but PyPI is the conventional path and publishing is a
   deliberate owner decision, not a build step.
2. **The engine wheel is binary-only.** `omna-pii-mask` publishes three architecture-specific
   wheels and **no sdist**. Homebrew's Python formula pattern (`virtualenv_install_with_resources`)
   expects source distributions it can build; an arch-specific binary wheel does not fit the
   one-formula-many-machines model cleanly. This is the hard blocker, and it is a *deliberate*
   property of the product (the kernel is closed-source), not an oversight.
3. **A tap repo must exist.** `brew install gaurjin/omna/omna` requires a public GitHub repo named
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

**Recommendation: Path B**, once there is a reason to spend the effort — it matches the product
(closed kernel, notarized Mac artifact already in the pipeline) and avoids arguing with Homebrew
about binary wheels. Path A fights the product's own architecture.

## What to do when the decision is made

```sh
# 1. Create the tap (this is a NEW PUBLIC REPO — ask first)
gh repo create gaurjin/homebrew-omna --public \
  --description "Homebrew tap for Omna — mask secrets and PII before your prompt leaves the machine"

# 2. Add the formula or cask
#    formula → Formula/omna.rb        →  brew install gaurjin/omna/omna
#    cask    → Casks/omna.rb          →  brew install --cask gaurjin/omna/omna

# 3. Verify before announcing it anywhere
brew tap gaurjin/omna
brew install gaurjin/omna/omna
brew test omna
brew audit --strict --online omna
```

Do not put the install line in the README until `brew audit --strict --online` passes on a clean
machine — a broken `brew install` in the README is worse than no `brew install` at all.
