# Trusting the Omna certificate in things that don't use the system keychain

**Read this only if a specific tool says "certificate error" or "self-signed certificate" after
`omna init`.** Most things work with no action: `omna init` puts "Omna Local Certificate
Authority" in the macOS System keychain, and Safari, Chrome, Edge, Brave, `curl`, Go programs,
and Claude Code all read from there.

## Why any of this is needed

To mask what a browser or an app sends, Omna has to open the envelope. HTTPS is designed to stop
exactly that, so `omna init` creates a certificate authority **on your machine**, keeps its
private key in `~/.omna/ca` (owner-only), and trusts it locally. The key never leaves your Mac
and is different on every install — there is no shared Omna key that could be stolen once and
used against everyone.

Some runtimes ignore the system keychain and carry their **own** list of trusted authorities.
Those need to be told about the certificate separately. That is what this page is for.

The certificate file is:

```
~/.omna/ca/mitmproxy-ca-cert.pem
```

---

## Firefox

Firefox keeps its own trust store. One switch makes it read the system one:

1. Open `about:config`
2. Accept the warning
3. Search for `security.enterprise_roots.enabled`
4. Set it to **true**
5. Restart Firefox

If you would rather import the file by hand instead:
`Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import`,
pick `~/.omna/ca/mitmproxy-ca-cert.pem`, and tick **Trust this CA to identify websites**.

## Node.js

Node ignores the system keychain entirely. Point it at the file:

```bash
export NODE_EXTRA_CA_CERTS="$HOME/.omna/ca/mitmproxy-ca-cert.pem"
```

Put that line in `~/.zshrc` to make it stick. `omna init` already does this for VS Code, which is
the common case; this is for Node you run yourself.

## Python (`requests`, `httpx`, `pip`, `urllib3`)

Python uses the `certifi` bundle, not the system keychain:

```bash
export REQUESTS_CA_BUNDLE="$HOME/.omna/ca/mitmproxy-ca-cert.pem"   # requests, pip
export SSL_CERT_FILE="$HOME/.omna/ca/mitmproxy-ca-cert.pem"        # httpx, urllib, aiohttp
```

Both are needed — different libraries read different variables. For `pip` specifically you can
also use `pip config set global.cert ~/.omna/ca/mitmproxy-ca-cert.pem`.

## Java / JVM tools

```bash
sudo keytool -importcert -trustcacerts -alias omna \
  -file ~/.omna/ca/mitmproxy-ca-cert.pem \
  -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit
```

## Go

Go uses the system keychain on macOS, so it normally needs nothing. If you built with
`CGO_ENABLED=0`, set `SSL_CERT_FILE` as in the Python section.

## Ruby / `gem` / Bundler

```bash
export SSL_CERT_FILE="$HOME/.omna/ca/mitmproxy-ca-cert.pem"
```

## Deno / Bun

```bash
export DENO_CERT="$HOME/.omna/ca/mitmproxy-ca-cert.pem"
export NODE_EXTRA_CA_CERTS="$HOME/.omna/ca/mitmproxy-ca-cert.pem"   # Bun
```

## `curl` and `wget`

Both use the system keychain on macOS and need nothing. If you use a Homebrew `curl` built
against its own bundle: `curl --cacert ~/.omna/ca/mitmproxy-ca-cert.pem ...`, or set
`CURL_CA_BUNDLE` to the same path.

---

## Linux distributions

Omna's proxy is macOS-only today (see the "Honest limits" section of the README), but if you are
running the certificate against a Linux box, the system store is updated like this:

**Debian / Ubuntu**

```bash
sudo cp ~/.omna/ca/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/omna.crt
sudo update-ca-certificates
```

**Fedora / RHEL / CentOS**

```bash
sudo cp ~/.omna/ca/mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/omna.pem
sudo update-ca-trust
```

**Arch**

```bash
sudo trust anchor --store ~/.omna/ca/mitmproxy-ca-cert.pem
```

**Alpine**

```bash
sudo cp ~/.omna/ca/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/omna.crt
sudo update-ca-certificates
```

---

## What will never work, on purpose

Some apps **pin** their certificate: they check the fingerprint themselves and reject anything
else, no matter what your trust store says. Omna does not try to defeat that. It refuses the
request rather than sending it unmasked, and names the app:

```
refused:      SomeApp → api.example.com ×3 (pinned)  → omna bypass app "SomeApp"
```

Run that `omna bypass` command if you would rather that app's traffic go straight out untouched.
It is still written to your receipts either way, so a bypass is never silent.

## Removing all of it

```bash
omna uninstall
```

That untrusts the certificate, removes the system proxy, and deletes `~/.omna`. Environment
variables you set by hand in `~/.zshrc` are yours to remove — Omna never edits that file.
