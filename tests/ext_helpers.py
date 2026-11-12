"""How Omna for Chrome calls the curl command's extension-only endpoints:
the old tag plus a signature made with the secret Chrome hands only to the
extension (finding 6). ``auth=EXT`` signs each request from its final bytes;
each test has its own OMNA_HOME, so its own secret."""

import httpx

from omna_plugin import extension_auth


class ExtAuth(httpx.Auth):
    requires_request_body = True

    def auth_flow(self, request):
        request.headers["x-omna-extension"] = "1"
        request.headers.update(extension_auth.sign(request.method, request.url.path, request.content))
        yield request


EXT = ExtAuth()
