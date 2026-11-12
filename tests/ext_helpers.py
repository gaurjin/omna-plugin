"""Headers Omna for Chrome sends to the curl command's extension-only
endpoints: the old tag plus the secret Chrome hands only to the extension
(finding 6). Built per request: each test has its own OMNA_HOME, so its own
secret."""

from omna_plugin import extension_auth


def ext_hdr() -> dict[str, str]:
    return {"x-omna-extension": "1", extension_auth.HEADER: extension_auth.ensure_token()}
