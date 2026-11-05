"""
Compressed request bodies: a client may gzip what it sends (`Content-Encoding: gzip`),
which matters for batches of events. The body is decompressed before the route sees it,
up to MAX_DECOMPRESSED_BYTES, so a small compressed body cannot expand without limit
(a "zip bomb"): beyond it, 413.
"""
import zlib

from starlette.responses import JSONResponse

MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024


class GzipRequestMiddleware:
    def __init__(self, app, max_size: int = MAX_DECOMPRESSED_BYTES):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        encoding = headers.get(b"content-encoding", b"").decode("latin-1").strip().lower()
        if encoding in ("", "identity"):
            await self.app(scope, receive, send)
            return
        if encoding != "gzip":
            await JSONResponse({"detail": f"Content-Encoding {encoding} is not supported; send gzip or nothing"}, status_code=415)(scope, receive, send)
            return

        compressed = b""
        while True:
            message = await receive()
            compressed += message.get("body", b"")
            if len(compressed) > self.max_size:
                await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body"):
                break
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip framing
        try:
            body = inflater.decompress(compressed, self.max_size + 1)
            if len(body) > self.max_size or inflater.unconsumed_tail:
                await JSONResponse({"detail": "Request body too large once decompressed"}, status_code=413)(scope, receive, send)
                return
        except zlib.error:
            await JSONResponse({"detail": "The body is not valid gzip"}, status_code=400)(scope, receive, send)
            return

        new_headers = [(k, v) for k, v in scope["headers"] if k not in (b"content-encoding", b"content-length")]
        new_headers.append((b"content-length", str(len(body)).encode()))
        scope = {**scope, "headers": new_headers}
        sent = False

        async def replay():
            nonlocal sent
            if sent:
                return await receive()  # after the body: disconnects and the like
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)
