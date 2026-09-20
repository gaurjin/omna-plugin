# Software Bill of Materials

`docs/sbom.cdx.json` lists every component the plugin ships, in
[CycloneDX](https://cyclonedx.org/) 1.5 format — the format most enterprise
security reviews ask for by name.

## Regenerating it

```sh
.venv/bin/python scripts/make-sbom.py
```

Run this after **any** dependency change and commit the result. The source of
truth is `uv.lock`, not whatever happens to be in a virtualenv, because the
lockfile is what a user's `uv tool install` actually resolves.

## What is in it

67 components. The one that always gets asked about:

| | |
|---|---|
| `omna-pii-mask` | The masking engine. **Closed source.** Distributed as a compiled binary wheel (three architecture-specific builds, no source distribution), built in CI from a private repository. |

Everything else is an ordinary open-source Python dependency: `httpx`,
`starlette`, `uvicorn`, `mitmproxy`, `cryptography`, `pystray`, `pillow`,
`ruamel.yaml` and their transitive dependencies.

## Questions a reviewer usually asks next

**"Is the engine open source?"** No, and deliberately. The detection logic is
the product. The plugin shell around it is MIT and public; the kernel is not.

**"How do you know the model hasn't been tampered with?"** Every file of the
detection model is verified against a SHA-256 pinned inside the engine before
it is loaded. `omna verify-model` re-checks on demand. See `SECURITY.md`.

**"What does it send?"** The user's own request, to the provider they were
already using. Nothing else, unless they turned on crash reports — which are
off by default, masked before they are written to disk, and never contain
prompts. See `SECURITY.md`.

**"Are releases signed?"** See `docs/signing.md`.
