"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience using Litestar.
"""

import asyncio
import base64
import json
import os
import random
import time
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional

import brotli as brotli_module
from litestar import (
    Controller,
    Litestar,
    MediaType,
    Request,
    Response,
    delete,
    get,
    patch,
    post,
    put,
)
from litestar.config.compression import CompressionConfig
from litestar.config.cors import CORSConfig
from litestar.contrib.jinja import JinjaTemplateEngine
from litestar.datastructures import Cookie, Headers, ResponseHeader, State
from litestar.exceptions import HTTPException, NotFoundException
from litestar.openapi.config import OpenAPIConfig
from litestar.response import Redirect, Stream, Template
from litestar.static_files import create_static_files_router
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_206_PARTIAL_CONTENT,
    HTTP_302_FOUND,
    HTTP_304_NOT_MODIFIED,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,
)
from litestar.template.config import TemplateConfig

from . import filters
from .helpers import (
    ANGRY_ASCII,
    H,
    ROBOT_TXT,
    check_basic_auth,
    check_digest_auth,
    digest_challenge_response,
    get_dict,
    get_headers,
    get_request_range,
    next_stale_after_value,
    parse_multi_value_header,
    secure_cookie,
    status_code,
)
from .structures import CaseInsensitiveDict
from .utils import weighted_choice

# Get version
VERSION_FILE = Path(__file__).parent / "VERSION"
version = VERSION_FILE.read_text().strip()

# Template directory
tmpl_dir = Path(__file__).parent / "templates"

ENV_COOKIES = (
    "_gauges_unique",
    "_gauges_unique_year",
    "_gauges_unique_month",
    "_gauges_unique_day",
    "_gauges_unique_hour",
    "__utmz",
    "__utma",
    "__utmb",
)


def jsonify_response(data: Dict[str, Any], status_code: int = 200) -> Response:
    """Return a JSON response with a trailing newline."""
    json_str = json.dumps(data, indent=2, sort_keys=True)
    if not json_str.endswith("\n"):
        json_str += "\n"
    return Response(
        content=json_str,
        status_code=status_code,
        media_type=MediaType.JSON,
    )


class HttpBinController(Controller):
    """Main controller for all httpbin endpoints."""

    path = "/"

    @get("/legacy", media_type=MediaType.HTML, tags=["Response formats"])
    async def view_landing_page(self) -> Template:
        """Generates Landing Page in legacy layout."""
        return Template(template_name="index.html")

    @get("/html", media_type=MediaType.HTML, tags=["Response formats"])
    async def view_html_page(self) -> Template:
        """Returns a simple HTML document."""
        return Template(template_name="moby.html")

    @get("/robots.txt", media_type=MediaType.TEXT, tags=["Response formats"])
    async def view_robots_page(self) -> Response[str]:
        """Returns some robots.txt rules."""
        return Response(content=ROBOT_TXT, media_type=MediaType.TEXT)

    @get("/deny", media_type=MediaType.TEXT, tags=["Response formats"])
    async def view_deny_page(self) -> Response[str]:
        """Returns page denied by robots.txt rules."""
        return Response(content=ANGRY_ASCII, media_type=MediaType.TEXT)

    @get("/ip", tags=["Request inspection"])
    async def view_origin(self, request: Request) -> Response:
        """Returns the requester's IP Address."""
        origin = request.headers.get("X-Forwarded-For", request.client.host if request.client else "")
        return jsonify_response({"origin": origin})

    @get("/uuid", tags=["Dynamic data"])
    async def view_uuid(self) -> Response:
        """Return a UUID4."""
        return jsonify_response({"uuid": str(uuid.uuid4())})

    @get("/headers", tags=["Request inspection"])
    async def view_headers(self, request: Request) -> Response:
        """Return the incoming request's HTTP headers."""
        return jsonify_response(get_dict(request, "headers"))

    @get("/user-agent", tags=["Request inspection"])
    async def view_user_agent(self, request: Request) -> Response:
        """Return the incoming requests's User-Agent header."""
        headers = get_headers(request)
        return jsonify_response({"user-agent": headers.get("user-agent", "")})

    @get("/get", tags=["HTTP Methods"])
    async def view_get(self, request: Request) -> Response:
        """The request's query parameters."""
        return jsonify_response(get_dict(request, "url", "args", "headers", "origin"))

    @get("/anything", tags=["Anything"])
    @post("/anything", tags=["Anything"])
    @put("/anything", tags=["Anything"])
    @delete("/anything", tags=["Anything"])
    @patch("/anything", tags=["Anything"])
    @get("/anything/{anything:path}", tags=["Anything"])
    @post("/anything/{anything:path}", tags=["Anything"])
    @put("/anything/{anything:path}", tags=["Anything"])
    @delete("/anything/{anything:path}", tags=["Anything"])
    @patch("/anything/{anything:path}", tags=["Anything"])
    async def view_anything(self, request: Request, anything: Optional[str] = None) -> Response:
        """Returns anything passed in request data."""
        return jsonify_response(
            get_dict(
                request,
                "url",
                "args",
                "headers",
                "origin",
                "method",
                "form",
                "data",
                "files",
                "json",
            )
        )

    @post("/post", tags=["HTTP Methods"])
    async def view_post(self, request: Request) -> Response:
        """The request's POST parameters."""
        return jsonify_response(
            get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
        )

    @put("/put", tags=["HTTP Methods"])
    async def view_put(self, request: Request) -> Response:
        """The request's PUT parameters."""
        return jsonify_response(
            get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
        )

    @patch("/patch", tags=["HTTP Methods"])
    async def view_patch(self, request: Request) -> Response:
        """The request's PATCH parameters."""
        return jsonify_response(
            get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
        )

    @delete("/delete", tags=["HTTP Methods"], status_code=200)
    async def view_delete(self, request: Request) -> Response:
        """The request's DELETE parameters."""
        return jsonify_response(
            get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
        )

    @get("/gzip", tags=["Response formats"])
    async def view_gzip_encoded_content(self, request: Request) -> Response:
        """Returns GZip-encoded data."""
        data = get_dict(request, "origin", "headers", method=request.method, gzipped=True)
        return filters.gzip_response(jsonify_response(data))

    @get("/deflate", tags=["Response formats"])
    async def view_deflate_encoded_content(self, request: Request) -> Response:
        """Returns Deflate-encoded data."""
        data = get_dict(request, "origin", "headers", method=request.method, deflated=True)
        return filters.deflate_response(jsonify_response(data))

    @get("/brotli", tags=["Response formats"])
    async def view_brotli_encoded_content(self, request: Request) -> Response:
        """Returns Brotli-encoded data."""
        data = get_dict(request, "origin", "headers", method=request.method, brotli=True)
        return filters.brotli_response(jsonify_response(data))

    @get("/redirect/{n:int}", tags=["Redirects"])
    async def redirect_n_times(self, request: Request, n: int) -> Response:
        """302 Redirects n times."""
        assert n > 0

        absolute = request.query_params.get("absolute", "false").lower() == "true"

        if n == 1:
            if absolute:
                return Redirect(path=str(request.url_for("HttpBinController.view_get")))
            return Redirect(path="/get")

        if absolute:
            url = str(request.url_for("HttpBinController.absolute_redirect_n_times", n=n - 1))
        else:
            url = str(request.url_for("HttpBinController.relative_redirect_n_times", n=n - 1))

        return Redirect(path=url)

    @get("/redirect-to", tags=["Redirects"])
    @post("/redirect-to", tags=["Redirects"])
    @put("/redirect-to", tags=["Redirects"])
    @delete("/redirect-to", tags=["Redirects"])
    @patch("/redirect-to", tags=["Redirects"])
    async def redirect_to(self, request: Request) -> Response:
        """302/3XX Redirects to the given URL."""
        args = CaseInsensitiveDict(request.query_params.items())

        redirect_status_code = 302
        if "status_code" in args:
            status_code_val = int(args["status_code"])
            if 300 <= status_code_val < 400:
                redirect_status_code = status_code_val

        url = args.get("url", "/")

        return Response(
            content=b"",
            status_code=redirect_status_code,
            headers={"Location": url},
        )

    @get("/relative-redirect/{n:int}", tags=["Redirects"])
    async def relative_redirect_n_times(self, request: Request, n: int) -> Response:
        """Relatively 302 Redirects n times."""
        assert n > 0

        if n == 1:
            return Response(
                content=b"",
                status_code=302,
                headers={"Location": "/get"},
            )

        return Response(
            content=b"",
            status_code=302,
            headers={"Location": f"/relative-redirect/{n - 1}"},
        )

    @get("/absolute-redirect/{n:int}", tags=["Redirects"])
    async def absolute_redirect_n_times(self, request: Request, n: int) -> Response:
        """Absolutely 302 Redirects n times."""
        assert n > 0

        if n == 1:
            return Redirect(path=str(request.url_for("HttpBinController.view_get")))

        return Redirect(
            path=str(request.url_for("HttpBinController.absolute_redirect_n_times", n=n - 1))
        )

    @get("/stream/{n:int}", tags=["Dynamic data"])
    async def stream_n_messages(self, request: Request, n: int) -> Stream:
        """Stream n JSON responses."""
        response_data = get_dict(request, "url", "args", "headers", "origin")
        n = min(n, 100)

        async def generate_stream() -> AsyncGenerator[bytes, None]:
            for i in range(n):
                response_data["id"] = i
                yield (json.dumps(response_data) + "\n").encode()

        return Stream(generate_stream(), media_type=MediaType.JSON)

    @get("/status/{codes:path}", tags=["Status codes"])
    @post("/status/{codes:path}", tags=["Status codes"])
    @put("/status/{codes:path}", tags=["Status codes"])
    @delete("/status/{codes:path}", tags=["Status codes"])
    @patch("/status/{codes:path}", tags=["Status codes"])
    async def view_status_code(self, request: Request, codes: str) -> Response:
        """Return status code or random status code if more than one are given."""
        if "," not in codes:
            try:
                code = int(codes)
            except ValueError:
                return Response(content="Invalid status code", status_code=400)
            return status_code(request, code)

        choices = []
        for choice in codes.split(","):
            if ":" not in choice:
                code = choice
                weight = 1
            else:
                code, weight = choice.split(":")

            try:
                choices.append((int(code), float(weight)))
            except ValueError:
                return Response(content="Invalid status code", status_code=400)

        code = weighted_choice(choices)
        return status_code(request, code)

    @get("/response-headers", tags=["Response inspection"])
    @post("/response-headers", tags=["Response inspection"])
    async def response_headers(self, request: Request) -> Response:
        """Returns a set of response headers from the query string."""
        headers_dict = dict(request.query_params.items())

        # Build response data
        response_data = {}
        for key, value in headers_dict.items():
            response_data[key] = value

        # Create response with custom headers
        return Response(
            content=json.dumps(response_data, indent=2) + "\n",
            media_type=MediaType.JSON,
            headers=headers_dict,
        )

    @get("/cookies", tags=["Cookies"])
    async def view_cookies(self, request: Request) -> Response:
        """Returns cookie data."""
        cookies = dict(request.cookies.items())

        # Hide environment cookies unless show_env is in query params
        if "show_env" not in request.query_params:
            for key in ENV_COOKIES:
                cookies.pop(key, None)

        return jsonify_response({"cookies": cookies})

    @get("/forms/post", media_type=MediaType.HTML, tags=["Cookies"])
    async def view_forms_post(self) -> Template:
        """Simple HTML form."""
        return Template(template_name="forms-post.html")

    @get("/cookies/set/{name:str}/{value:str}", tags=["Cookies"])
    async def set_cookie(self, request: Request, name: str, value: str) -> Response:
        """Sets a cookie and redirects to cookie list."""
        response = Redirect(path="/cookies")
        response.set_cookie(
            key=name,
            value=value,
            secure=secure_cookie(request),
        )
        return response

    @get("/cookies/set", tags=["Cookies"])
    async def set_cookies(self, request: Request) -> Response:
        """Sets cookie(s) as provided by the query string and redirects to cookie list."""
        cookies = dict(request.query_params.items())
        response = Redirect(path="/cookies")

        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, secure=secure_cookie(request))

        return response

    @get("/cookies/delete", tags=["Cookies"])
    async def delete_cookies(self, request: Request) -> Response:
        """Deletes cookie(s) as provided by the query string and redirects to cookie list."""
        cookies = dict(request.query_params.items())
        response = Redirect(path="/cookies")

        for key in cookies.keys():
            response.delete_cookie(key=key)

        return response

    @get("/basic-auth/{user:str}/{passwd:str}", tags=["Auth"])
    async def basic_auth(self, request: Request, user: str = "user", passwd: str = "passwd") -> Response:
        """Prompts the user for authorization using HTTP Basic Auth."""
        if not check_basic_auth(request, user, passwd):
            return status_code(request, 401)

        return jsonify_response({"authenticated": True, "user": user})

    @get("/hidden-basic-auth/{user:str}/{passwd:str}", tags=["Auth"])
    async def hidden_basic_auth(self, request: Request, user: str = "user", passwd: str = "passwd") -> Response:
        """Prompts the user for authorization using HTTP Basic Auth."""
        if not check_basic_auth(request, user, passwd):
            return status_code(request, 404)

        return jsonify_response({"authenticated": True, "user": user})

    @get("/bearer", tags=["Auth"])
    async def bearer_auth(self, request: Request) -> Response:
        """Prompts the user for authorization using bearer authentication."""
        authorization = request.headers.get("Authorization", "")

        if not (authorization and authorization.startswith("Bearer ")):
            return Response(
                content=b"",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = authorization[len("Bearer "):]
        return jsonify_response({"authenticated": True, "token": token})

    @get("/digest-auth/{qop:str}/{user:str}/{passwd:str}", tags=["Auth"])
    async def digest_auth_md5(
        self, request: Request, qop: Optional[str] = None, user: str = "user", passwd: str = "passwd"
    ) -> Response:
        """Prompts the user for authorization using Digest Auth."""
        return await self.digest_auth(request, qop, user, passwd, "MD5", "never")

    @get("/digest-auth/{qop:str}/{user:str}/{passwd:str}/{algorithm:str}", tags=["Auth"])
    async def digest_auth_nostale(
        self,
        request: Request,
        qop: Optional[str] = None,
        user: str = "user",
        passwd: str = "passwd",
        algorithm: str = "MD5",
    ) -> Response:
        """Prompts the user for authorization using Digest Auth + Algorithm."""
        return await self.digest_auth(request, qop, user, passwd, algorithm, "never")

    @get("/digest-auth/{qop:str}/{user:str}/{passwd:str}/{algorithm:str}/{stale_after:str}", tags=["Auth"])
    async def digest_auth(
        self,
        request: Request,
        qop: Optional[str] = None,
        user: str = "user",
        passwd: str = "passwd",
        algorithm: str = "MD5",
        stale_after: str = "never",
    ) -> Response:
        """Prompts the user for authorization using Digest Auth + Algorithm."""
        require_cookie_handling = request.query_params.get("require-cookie", "").lower() in ("1", "t", "true")

        if algorithm not in ("MD5", "SHA-256", "SHA-512"):
            algorithm = "MD5"

        if qop not in ("auth", "auth-int"):
            qop = None

        authorization = request.headers.get("Authorization")
        credentials = None

        if authorization:
            from .helpers import parse_authorization_header
            credentials = parse_authorization_header(authorization)

        if (
            not authorization
            or not credentials
            or credentials.type.lower() != "digest"
            or (require_cookie_handling and "Cookie" not in request.headers)
        ):
            response = digest_challenge_response(request, qop, algorithm)
            response.set_cookie("stale_after", value=stale_after)
            response.set_cookie("fake", value="fake_value")
            return response

        if require_cookie_handling and request.cookies.get("fake") != "fake_value":
            response = jsonify_response({"errors": ["missing cookie set on challenge"]}, status_code=403)
            response.set_cookie("fake", value="fake_value")
            return response

        current_nonce = credentials.get("nonce")
        stale_after_value = request.cookies.get("stale_after")

        if (
            "last_nonce" in request.cookies
            and current_nonce == request.cookies.get("last_nonce")
            or stale_after_value == "0"
        ):
            response = digest_challenge_response(request, qop, algorithm, True)
            response.set_cookie("stale_after", value=stale_after)
            response.set_cookie("last_nonce", value=current_nonce)
            response.set_cookie("fake", value="fake_value")
            return response

        if not check_digest_auth(request, user, passwd):
            response = digest_challenge_response(request, qop, algorithm, False)
            response.set_cookie("stale_after", value=stale_after)
            response.set_cookie("last_nonce", value=current_nonce)
            response.set_cookie("fake", value="fake_value")
            return response

        response = jsonify_response({"authenticated": True, "user": user})
        response.set_cookie("fake", value="fake_value")

        if stale_after_value:
            response.set_cookie("stale_after", value=next_stale_after_value(stale_after_value))

        return response

    @get("/delay/{delay:int}", tags=["Dynamic data"])
    @post("/delay/{delay:int}", tags=["Dynamic data"])
    @put("/delay/{delay:int}", tags=["Dynamic data"])
    @delete("/delay/{delay:int}", tags=["Dynamic data"])
    @patch("/delay/{delay:int}", tags=["Dynamic data"])
    async def delay_response(self, request: Request, delay: int) -> Response:
        """Returns a delayed response (max of 10 seconds)."""
        delay = min(float(delay), 10)
        await asyncio.sleep(delay)

        return jsonify_response(
            get_dict(request, "url", "args", "form", "data", "origin", "headers", "files")
        )

    @get("/drip", tags=["Dynamic data"])
    async def drip(self, request: Request) -> Stream:
        """Drips data over a duration after an optional initial delay."""
        args = CaseInsensitiveDict(request.query_params.items())
        duration = float(args.get("duration", 2))
        numbytes = min(int(args.get("numbytes", 10)), 10 * 1024 * 1024)  # 10MB limit
        code = int(args.get("code", 200))

        if numbytes <= 0:
            return Response(content="number of bytes must be positive", status_code=400)

        delay = float(args.get("delay", 0))
        if delay > 0:
            await asyncio.sleep(delay)

        pause = duration / numbytes

        async def generate_bytes() -> AsyncGenerator[bytes, None]:
            for i in range(numbytes):
                yield b"*"
                await asyncio.sleep(pause)

        return Stream(
            generate_bytes(),
            media_type="application/octet-stream",
            headers={"Content-Length": str(numbytes)},
            status_code=code,
        )

    @get("/base64/{value:str}", media_type=MediaType.TEXT, tags=["Dynamic data"])
    async def decode_base64(self, value: str) -> Response:
        """Decodes base64url-encoded string."""
        encoded = value.encode("utf-8")
        try:
            decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")
            return Response(content=decoded, media_type=MediaType.TEXT)
        except Exception:
            return Response(
                content="Incorrect Base64 data try: SFRUUEJJTiBpcyBhd2Vzb21l",
                media_type=MediaType.TEXT,
            )

    @get("/cache", tags=["Response inspection"])
    async def cache(self, request: Request) -> Response:
        """Returns a 304 if an If-Modified-Since header or If-None-Match is present."""
        is_conditional = request.headers.get("If-Modified-Since") or request.headers.get("If-None-Match")

        if is_conditional is None:
            response = await self.view_get(request)
            from werkzeug.http import http_date

            response.headers["Last-Modified"] = http_date()
            response.headers["ETag"] = uuid.uuid4().hex
            return response
        else:
            return status_code(request, 304)

    @get("/etag/{etag:str}", tags=["Response inspection"])
    async def etag(self, request: Request, etag: str) -> Response:
        """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers."""
        if_none_match = parse_multi_value_header(request.headers.get("If-None-Match"))
        if_match = parse_multi_value_header(request.headers.get("If-Match"))

        if if_none_match:
            if etag in if_none_match or "*" in if_none_match:
                response = status_code(request, 304)
                response.headers["ETag"] = etag
                return response
        elif if_match:
            if etag not in if_match and "*" not in if_match:
                return status_code(request, 412)

        # Normal response
        response = await self.view_get(request)
        response.headers["ETag"] = etag
        return response

    @get("/cache/{value:int}", tags=["Response inspection"])
    async def cache_control(self, request: Request, value: int) -> Response:
        """Sets a Cache-Control header for n seconds."""
        response = await self.view_get(request)
        response.headers["Cache-Control"] = f"public, max-age={value}"
        return response

    @get("/encoding/utf8", media_type=MediaType.HTML, tags=["Response formats"])
    async def encoding(self) -> Template:
        """Returns a UTF-8 encoded body."""
        return Template(template_name="UTF-8-demo.txt")

    @get("/bytes/{n:int}", tags=["Dynamic data"])
    async def random_bytes(self, request: Request, n: int) -> Response:
        """Returns n random bytes generated with given seed."""
        n = min(n, 100 * 1024)  # 100KB limit

        params = CaseInsensitiveDict(request.query_params.items())
        if "seed" in params:
            random.seed(int(params["seed"]))

        data = bytearray(random.randint(0, 255) for i in range(n))

        return Response(content=bytes(data), media_type="application/octet-stream")

    @get("/stream-bytes/{n:int}", tags=["Dynamic data"])
    async def stream_random_bytes(self, request: Request, n: int) -> Stream:
        """Streams n random bytes generated with given seed, at given chunk size per packet."""
        n = min(n, 100 * 1024)  # 100KB limit

        params = CaseInsensitiveDict(request.query_params.items())
        if "seed" in params:
            random.seed(int(params["seed"]))

        chunk_size = max(1, int(params.get("chunk_size", 10 * 1024)))

        async def generate_bytes() -> AsyncGenerator[bytes, None]:
            chunks = bytearray()
            for i in range(n):
                chunks.append(random.randint(0, 255))
                if len(chunks) == chunk_size:
                    yield bytes(chunks)
                    chunks = bytearray()

            if chunks:
                yield bytes(chunks)

        return Stream(generate_bytes(), media_type="application/octet-stream")

    @get("/range/{numbytes:int}", tags=["Dynamic data"])
    async def range_request(self, request: Request, numbytes: int) -> Response | Stream:
        """Streams n random bytes generated with given seed, at given chunk size per packet."""
        if numbytes <= 0 or numbytes > (100 * 1024):
            return Response(
                content="number of bytes must be in the range (0, 102400]",
                status_code=404,
                headers={
                    "ETag": f"range{numbytes}",
                    "Accept-Ranges": "bytes",
                },
            )

        params = CaseInsensitiveDict(request.query_params.items())
        chunk_size = max(1, int(params.get("chunk_size", 10 * 1024)))
        duration = float(params.get("duration", 0))
        pause_per_byte = duration / numbytes

        request_headers = get_headers(request)
        first_byte_pos, last_byte_pos = get_request_range(request_headers, numbytes)
        range_length = (last_byte_pos + 1) - first_byte_pos

        if (
            first_byte_pos > last_byte_pos
            or first_byte_pos not in range(0, numbytes)
            or last_byte_pos not in range(0, numbytes)
        ):
            return Response(
                content=b"",
                status_code=416,
                headers={
                    "ETag": f"range{numbytes}",
                    "Accept-Ranges": "bytes",
                    "Content-Range": f"bytes */{numbytes}",
                    "Content-Length": "0",
                },
            )

        async def generate_bytes() -> AsyncGenerator[bytes, None]:
            chunks = bytearray()
            for i in range(first_byte_pos, last_byte_pos + 1):
                # Predictable data generation
                chunks.append(ord("a") + (i % 26))
                if len(chunks) == chunk_size:
                    yield bytes(chunks)
                    await asyncio.sleep(pause_per_byte * chunk_size)
                    chunks = bytearray()

            if chunks:
                await asyncio.sleep(pause_per_byte * len(chunks))
                yield bytes(chunks)

        content_range = f"bytes {first_byte_pos}-{last_byte_pos}/{numbytes}"
        response_headers = {
            "ETag": f"range{numbytes}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(range_length),
            "Content-Range": content_range,
        }

        status = 200 if (first_byte_pos == 0) and (last_byte_pos == (numbytes - 1)) else 206

        return Stream(
            generate_bytes(),
            media_type="application/octet-stream",
            headers=response_headers,
            status_code=status,
        )

    @get("/links/{n:int}/{offset:int}", media_type=MediaType.HTML, tags=["Dynamic data"])
    async def link_page(self, request: Request, n: int, offset: int) -> Response:
        """Generate a page containing n links to other pages which do the same."""
        n = min(max(1, n), 200)  # limit to between 1 and 200 links

        html = ["<html><head><title>Links</title></head><body>"]
        for i in range(n):
            if i == offset:
                html.append(f"{i} ")
            else:
                html.append(f"<a href='/links/{n}/{i}'>{i}</a> ")
        html.append("</body></html>")

        return Response(content="".join(html), media_type=MediaType.HTML)

    @get("/links/{n:int}", tags=["Dynamic data"])
    async def links(self, request: Request, n: int) -> Response:
        """Redirect to first links page."""
        return Redirect(path=f"/links/{n}/0")

    @get("/image", tags=["Images"])
    async def image(self, request: Request) -> Response:
        """Returns a simple image of the type suggest by the Accept header."""
        headers = get_headers(request)
        accept = headers.get("accept", "").lower()

        if not accept:
            return await self.image_png()

        if "image/webp" in accept:
            return await self.image_webp()
        elif "image/svg+xml" in accept:
            return await self.image_svg()
        elif "image/jpeg" in accept:
            return await self.image_jpeg()
        elif "image/png" in accept or "image/*" in accept:
            return await self.image_png()
        else:
            return status_code(request, 406)

    @get("/image/png", tags=["Images"])
    async def image_png(self) -> Response:
        """Returns a simple PNG image."""
        data = self._resource("images/pig_icon.png")
        return Response(content=data, media_type="image/png")

    @get("/image/jpeg", tags=["Images"])
    async def image_jpeg(self) -> Response:
        """Returns a simple JPEG image."""
        data = self._resource("images/jackal.jpg")
        return Response(content=data, media_type="image/jpeg")

    @get("/image/webp", tags=["Images"])
    async def image_webp(self) -> Response:
        """Returns a simple WEBP image."""
        data = self._resource("images/wolf_1.webp")
        return Response(content=data, media_type="image/webp")

    @get("/image/svg", tags=["Images"])
    async def image_svg(self) -> Response:
        """Returns a simple SVG image."""
        data = self._resource("images/svg_logo.svg")
        return Response(content=data, media_type="image/svg+xml")

    def _resource(self, filename: str) -> bytes:
        """Load a resource file."""
        path = tmpl_dir / filename
        return path.read_bytes()

    @get("/xml", media_type="application/xml", tags=["Response formats"])
    async def xml(self) -> Template:
        """Returns a simple XML document."""
        return Template(template_name="sample.xml")

    @get("/json", tags=["Response formats"])
    async def a_json_endpoint(self) -> Response:
        """Returns a simple JSON document."""
        return jsonify_response(
            {
                "slideshow": {
                    "title": "Sample Slide Show",
                    "date": "date of publication",
                    "author": "Yours Truly",
                    "slides": [
                        {"type": "all", "title": "Wake up to WonderWidgets!"},
                        {
                            "type": "all",
                            "title": "Overview",
                            "items": [
                                "Why <em>WonderWidgets</em> are great",
                                "Who <em>buys</em> WonderWidgets",
                            ],
                        },
                    ],
                }
            }
        )


# CORS configuration
cors_config = CORSConfig(
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True,
    max_age=3600,
)

# OpenAPI configuration
openapi_config = OpenAPIConfig(
    title="httpbin.org",
    version=version,
    description=(
        "A simple HTTP Request & Response Service.<br/> <br/> "
        "<b>Run locally: </b> <code>$ docker run -p 80:80 kennethreitz/httpbin</code>"
    ),
    contact={
        "name": "Kenneth Reitz",
        "email": "me@kennethreitz.org",
        "url": "https://kennethreitz.org",
    },
)

# Template configuration
template_config = TemplateConfig(
    directory=tmpl_dir,
    engine=JinjaTemplateEngine,
)

# Create the Litestar app
app = Litestar(
    route_handlers=[HttpBinController],
    cors_config=cors_config,
    openapi_config=openapi_config,
    template_config=template_config,
    debug=bool(os.environ.get("DEBUG")),
)


if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)
