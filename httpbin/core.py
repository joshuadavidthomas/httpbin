"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience using Litestar.
"""

import asyncio
import base64
import os
import random
import time
import uuid
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator

import brotli as brotli_module
from litestar import Litestar, MediaType, Request, Response, delete, get, patch, post, put
from litestar.config.cors import CORSConfig
from litestar.contrib.jinja import JinjaTemplateEngine
from litestar.exceptions import HTTPException
from litestar.openapi.config import OpenAPIConfig
from litestar.params import Parameter
from litestar.response import Redirect, Stream, Template
from litestar.serialization import encode_json
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_206_PARTIAL_CONTENT,
    HTTP_301_MOVED_PERMANENTLY,
    HTTP_302_FOUND,
    HTTP_303_SEE_OTHER,
    HTTP_304_NOT_MODIFIED,
    HTTP_307_TEMPORARY_REDIRECT,
    HTTP_308_PERMANENT_REDIRECT,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_406_NOT_ACCEPTABLE,
    HTTP_412_PRECONDITION_FAILED,
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
    parse_authorization_header,
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

ENV_COOKIES: frozenset[str] = frozenset([
    "_gauges_unique",
    "_gauges_unique_year",
    "_gauges_unique_month",
    "_gauges_unique_day",
    "_gauges_unique_hour",
    "__utmz",
    "__utma",
    "__utmb",
])


def load_resource(filename: str) -> bytes:
    """Load a resource file."""
    path = tmpl_dir / filename
    return path.read_bytes()


# Route Handlers


@get("/legacy", media_type=MediaType.HTML, tags=["Response formats"])
async def view_landing_page() -> Template:
    """Generates Landing Page in legacy layout."""
    return Template(template_name="index.html")


@get("/html", media_type=MediaType.HTML, tags=["Response formats"])
async def view_html_page() -> Template:
    """Returns a simple HTML document."""
    return Template(template_name="moby.html")


@get("/robots.txt", media_type=MediaType.TEXT, tags=["Response formats"])
async def view_robots_page() -> Response[str]:
    """Returns some robots.txt rules."""
    return Response(content=ROBOT_TXT, media_type=MediaType.TEXT)


@get("/deny", media_type=MediaType.TEXT, tags=["Response formats"])
async def view_deny_page() -> Response[str]:
    """Returns page denied by robots.txt rules."""
    return Response(content=ANGRY_ASCII, media_type=MediaType.TEXT)


@get("/ip", tags=["Request inspection"])
async def view_origin(request: Request) -> dict:
    """Returns the requester's IP Address."""
    origin = request.headers.get(
        "X-Forwarded-For", request.client.host if request.client else ""
    )
    return {"origin": origin}


@get("/uuid", tags=["Dynamic data"])
async def view_uuid() -> dict:
    """Return a UUID4."""
    return {"uuid": str(uuid.uuid4())}


@get("/headers", tags=["Request inspection"])
async def view_headers(request: Request) -> dict:
    """Return the incoming request's HTTP headers."""
    return await get_dict(request, "headers")


@get("/user-agent", tags=["Request inspection"])
async def view_user_agent(request: Request) -> dict:
    """Return the incoming requests's User-Agent header."""
    headers = get_headers(request)
    return {"user-agent": headers.get("user-agent", "")}


@get("/get", tags=["HTTP Methods"])
async def view_get(request: Request) -> dict:
    """The request's query parameters."""
    return await get_dict(request, "url", "args", "headers", "origin")


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
async def view_anything(request: Request, anything: str | None = None) -> dict:
    """Returns anything passed in request data."""
    return await get_dict(
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


@post("/post", tags=["HTTP Methods"])
async def view_post(request: Request) -> dict:
    """The request's POST parameters."""
    return await get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")


@put("/put", tags=["HTTP Methods"])
async def view_put(request: Request) -> dict:
    """The request's PUT parameters."""
    return await get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")


@patch("/patch", tags=["HTTP Methods"])
async def view_patch(request: Request) -> dict:
    """The request's PATCH parameters."""
    return await get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")


@delete("/delete", tags=["HTTP Methods"], status_code=HTTP_200_OK)
async def view_delete(request: Request) -> dict:
    """The request's DELETE parameters."""
    return await get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")


@get("/gzip", tags=["Response formats"])
async def view_gzip_encoded_content(request: Request) -> Response:
    """Returns GZip-encoded data."""
    data = await get_dict(request, "origin", "headers", method=request.method, gzipped=True)
    response = Response(content=encode_json(data), media_type=MediaType.JSON)
    return filters.gzip_response(response)


@get("/deflate", tags=["Response formats"])
async def view_deflate_encoded_content(request: Request) -> Response:
    """Returns Deflate-encoded data."""
    data = await get_dict(request, "origin", "headers", method=request.method, deflated=True)
    response = Response(content=encode_json(data), media_type=MediaType.JSON)
    return filters.deflate_response(response)


@get("/brotli", tags=["Response formats"])
async def view_brotli_encoded_content(request: Request) -> Response:
    """Returns Brotli-encoded data."""
    data = await get_dict(request, "origin", "headers", method=request.method, brotli=True)
    response = Response(content=encode_json(data), media_type=MediaType.JSON)
    return filters.brotli_response(response)


@get("/redirect/{n:int}", tags=["Redirects"])
async def redirect_n_times(
    request: Request,
    n: Annotated[int, Parameter(description="Number of redirects")],
) -> Response:
    """302 Redirects n times."""
    assert n > 0

    absolute = request.query_params.get("absolute", "false").lower() == "true"

    if n == 1:
        if absolute:
            return Redirect(path=str(request.url_for("view_get")))
        return Redirect(path="/get")

    if absolute:
        url = str(request.url_for("absolute_redirect_n_times", n=n - 1))
    else:
        url = str(request.url_for("relative_redirect_n_times", n=n - 1))

    return Redirect(path=url)


@get("/redirect-to", tags=["Redirects"])
@post("/redirect-to", tags=["Redirects"])
@put("/redirect-to", tags=["Redirects"])
@delete("/redirect-to", tags=["Redirects"])
@patch("/redirect-to", tags=["Redirects"])
async def redirect_to(request: Request) -> Response:
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
async def relative_redirect_n_times(request: Request, n: int) -> Response:
    """Relatively 302 Redirects n times."""
    assert n > 0

    if n == 1:
        return Response(
            content=b"",
            status_code=HTTP_302_FOUND,
            headers={"Location": "/get"},
        )

    return Response(
        content=b"",
        status_code=HTTP_302_FOUND,
        headers={"Location": f"/relative-redirect/{n - 1}"},
    )


@get("/absolute-redirect/{n:int}", tags=["Redirects"])
async def absolute_redirect_n_times(request: Request, n: int) -> Response:
    """Absolutely 302 Redirects n times."""
    assert n > 0

    if n == 1:
        return Redirect(path=str(request.url_for("view_get")))

    return Redirect(path=str(request.url_for("absolute_redirect_n_times", n=n - 1)))


@get("/stream/{n:int}", tags=["Dynamic data"])
async def stream_n_messages(
    request: Request,
    n: Annotated[int, Parameter(description="Number of messages to stream (max 100)")],
) -> Stream:
    """Stream n JSON responses."""
    response_data = await get_dict(request, "url", "args", "headers", "origin")
    n = min(n, 100)

    async def generate_stream() -> AsyncGenerator[bytes, None]:
        for i in range(n):
            response_data["id"] = i
            yield encode_json(response_data) + b"\n"

    return Stream(generate_stream(), media_type=MediaType.JSON)


@get("/status/{codes:path}", tags=["Status codes"])
@post("/status/{codes:path}", tags=["Status codes"])
@put("/status/{codes:path}", tags=["Status codes"])
@delete("/status/{codes:path}", tags=["Status codes"])
@patch("/status/{codes:path}", tags=["Status codes"])
async def view_status_code(request: Request, codes: str) -> Response:
    """Return status code or random status code if more than one are given."""
    if "," not in codes:
        try:
            code = int(codes)
        except ValueError:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid status code")
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
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid status code")

    code = weighted_choice(choices)
    return status_code(request, code)


@get("/response-headers", tags=["Response inspection"])
@post("/response-headers", tags=["Response inspection"])
async def response_headers(request: Request) -> Response:
    """Returns a set of response headers from the query string."""
    headers_dict = dict(request.query_params.items())

    # Return query params as JSON body AND as response headers
    return Response(
        content=headers_dict,
        headers=headers_dict,
    )


@get("/cookies", tags=["Cookies"])
async def view_cookies(request: Request) -> dict:
    """Returns cookie data."""
    cookies = dict(request.cookies.items())

    # Hide environment cookies unless show_env is in query params
    if "show_env" not in request.query_params:
        for key in ENV_COOKIES:
            cookies.pop(key, None)

    return {"cookies": cookies}


@get("/forms/post", media_type=MediaType.HTML, tags=["Cookies"])
async def view_forms_post() -> Template:
    """Simple HTML form."""
    return Template(template_name="forms-post.html")


@get("/cookies/set/{name:str}/{value:str}", tags=["Cookies"])
async def set_cookie(request: Request, name: str, value: str) -> Response:
    """Sets a cookie and redirects to cookie list."""
    response = Redirect(path="/cookies")
    response.set_cookie(
        key=name,
        value=value,
        secure=secure_cookie(request),
    )
    return response


@get("/cookies/set", tags=["Cookies"])
async def set_cookies(request: Request) -> Response:
    """Sets cookie(s) as provided by the query string and redirects to cookie list."""
    cookies = dict(request.query_params.items())
    response = Redirect(path="/cookies")

    for key, value in cookies.items():
        response.set_cookie(key=key, value=value, secure=secure_cookie(request))

    return response


@get("/cookies/delete", tags=["Cookies"])
async def delete_cookies(request: Request) -> Response:
    """Deletes cookie(s) as provided by the query string and redirects to cookie list."""
    cookies = dict(request.query_params.items())
    response = Redirect(path="/cookies")

    for key in cookies.keys():
        response.delete_cookie(key=key)

    return response


@get("/basic-auth/{user:str}/{passwd:str}", tags=["Auth"])
async def basic_auth(request: Request, user: str = "user", passwd: str = "passwd") -> dict | Response:
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code(request, 401)

    return {"authenticated": True, "user": user}


@get("/hidden-basic-auth/{user:str}/{passwd:str}", tags=["Auth"])
async def hidden_basic_auth(
    request: Request, user: str = "user", passwd: str = "passwd"
) -> dict | Response:
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code(request, 404)

    return {"authenticated": True, "user": user}


@get("/bearer", tags=["Auth"])
async def bearer_auth(request: Request) -> dict | Response:
    """Prompts the user for authorization using bearer authentication."""
    authorization = request.headers.get("Authorization", "")

    if not (authorization and authorization.startswith("Bearer ")):
        return Response(
            content=b"",
            status_code=HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[len("Bearer ") :]
    return {"authenticated": True, "token": token}


@get("/digest-auth/{qop:str}/{user:str}/{passwd:str}", tags=["Auth"])
async def digest_auth_md5(
    request: Request, qop: str | None = None, user: str = "user", passwd: str = "passwd"
) -> Response:
    """Prompts the user for authorization using Digest Auth."""
    return await digest_auth(request, qop, user, passwd, "MD5", "never")


@get("/digest-auth/{qop:str}/{user:str}/{passwd:str}/{algorithm:str}", tags=["Auth"])
async def digest_auth_nostale(
    request: Request,
    qop: str | None = None,
    user: str = "user",
    passwd: str = "passwd",
    algorithm: str = "MD5",
) -> Response:
    """Prompts the user for authorization using Digest Auth + Algorithm."""
    return await digest_auth(request, qop, user, passwd, algorithm, "never")


@get(
    "/digest-auth/{qop:str}/{user:str}/{passwd:str}/{algorithm:str}/{stale_after:str}",
    tags=["Auth"],
)
async def digest_auth(
    request: Request,
    qop: str | None = None,
    user: str = "user",
    passwd: str = "passwd",
    algorithm: str = "MD5",
    stale_after: str = "never",
) -> Response:
    """Prompts the user for authorization using Digest Auth + Algorithm."""
    require_cookie_handling = request.query_params.get("require-cookie", "").lower() in (
        "1",
        "t",
        "true",
    )

    if algorithm not in ("MD5", "SHA-256", "SHA-512"):
        algorithm = "MD5"

    if qop not in ("auth", "auth-int"):
        qop = None

    authorization = request.headers.get("Authorization")
    credentials = None

    if authorization:
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
        response = Response(
            content={"errors": ["missing cookie set on challenge"]},
            status_code=HTTP_403_FORBIDDEN,
            media_type=MediaType.JSON,
        )
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

    if not await check_digest_auth(request, user, passwd):
        response = digest_challenge_response(request, qop, algorithm, False)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("last_nonce", value=current_nonce)
        response.set_cookie("fake", value="fake_value")
        return response

    response = Response(
        content={"authenticated": True, "user": user},
        media_type=MediaType.JSON,
    )
    response.set_cookie("fake", value="fake_value")

    if stale_after_value:
        response.set_cookie("stale_after", value=next_stale_after_value(stale_after_value))

    return response


@get("/delay/{delay:int}", tags=["Dynamic data"])
@post("/delay/{delay:int}", tags=["Dynamic data"])
@put("/delay/{delay:int}", tags=["Dynamic data"])
@delete("/delay/{delay:int}", tags=["Dynamic data"])
@patch("/delay/{delay:int}", tags=["Dynamic data"])
async def delay_response(request: Request, delay: int) -> dict:
    """Returns a delayed response (max of 10 seconds)."""
    delay_seconds = min(float(delay), 10)
    await asyncio.sleep(delay_seconds)

    return await get_dict(request, "url", "args", "form", "data", "origin", "headers", "files")


@get("/drip", tags=["Dynamic data"])
async def drip(request: Request) -> Stream:
    """Drips data over a duration after an optional initial delay."""
    args = CaseInsensitiveDict(request.query_params.items())
    duration = float(args.get("duration", 2))
    numbytes = min(int(args.get("numbytes", 10)), 10 * 1024 * 1024)  # 10MB limit
    code = int(args.get("code", 200))

    if numbytes <= 0:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="number of bytes must be positive")

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
async def decode_base64(value: str) -> Response:
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
async def cache(request: Request) -> Response:
    """Returns a 304 if an If-Modified-Since header or If-None-Match is present."""
    is_conditional = request.headers.get("If-Modified-Since") or request.headers.get(
        "If-None-Match"
    )

    if is_conditional is None:
        data = await view_get(request)
        from werkzeug.http import http_date

        response = Response(content=data)
        response.headers["Last-Modified"] = http_date()
        response.headers["ETag"] = uuid.uuid4().hex
        return response
    else:
        return status_code(request, HTTP_304_NOT_MODIFIED)


@get("/etag/{etag:str}", tags=["Response inspection"])
async def etag(request: Request, etag: str) -> Response:
    """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers."""
    if_none_match = parse_multi_value_header(request.headers.get("If-None-Match"))
    if_match = parse_multi_value_header(request.headers.get("If-Match"))

    if if_none_match:
        if etag in if_none_match or "*" in if_none_match:
            response = status_code(request, HTTP_304_NOT_MODIFIED)
            response.headers["ETag"] = etag
            return response
    elif if_match:
        if etag not in if_match and "*" not in if_match:
            return status_code(request, HTTP_412_PRECONDITION_FAILED)

    # Normal response
    data = await view_get(request)
    response = Response(content=data)
    response.headers["ETag"] = etag
    return response


@get("/cache/{value:int}", tags=["Response inspection"])
async def cache_control(request: Request, value: int) -> Response:
    """Sets a Cache-Control header for n seconds."""
    data = await view_get(request)
    response = Response(content=data)
    response.headers["Cache-Control"] = f"public, max-age={value}"
    return response


@get("/encoding/utf8", media_type=MediaType.HTML, tags=["Response formats"])
async def encoding() -> Template:
    """Returns a UTF-8 encoded body."""
    return Template(template_name="UTF-8-demo.txt")


@get("/bytes/{n:int}", tags=["Dynamic data"])
async def random_bytes(
    request: Request,
    n: Annotated[int, Parameter(description="Number of random bytes to generate (max 100KB)")],
) -> Response:
    """Returns n random bytes generated with given seed."""
    n = min(n, 100 * 1024)  # 100KB limit

    params = CaseInsensitiveDict(request.query_params.items())
    if "seed" in params:
        random.seed(int(params["seed"]))

    data = bytearray(random.randint(0, 255) for i in range(n))

    return Response(content=bytes(data), media_type="application/octet-stream")


@get("/stream-bytes/{n:int}", tags=["Dynamic data"])
async def stream_random_bytes(request: Request, n: int) -> Stream:
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
async def range_request(request: Request, numbytes: int) -> Response | Stream:
    """Streams n random bytes generated with given seed, at given chunk size per packet."""
    if numbytes <= 0 or numbytes > (100 * 1024):
        return Response(
            content="number of bytes must be in the range (0, 102400]",
            status_code=HTTP_404_NOT_FOUND,
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
            status_code=HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,
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
async def link_page(request: Request, n: int, offset: int) -> Response:
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
async def links(request: Request, n: int) -> Response:
    """Redirect to first links page."""
    return Redirect(path=f"/links/{n}/0")


@get("/image", tags=["Images"])
async def image(request: Request) -> Response:
    """Returns a simple image of the type suggest by the Accept header."""
    headers = get_headers(request)
    accept = headers.get("accept", "").lower()

    if not accept:
        return await image_png()

    if "image/webp" in accept:
        return await image_webp()
    elif "image/svg+xml" in accept:
        return await image_svg()
    elif "image/jpeg" in accept:
        return await image_jpeg()
    elif "image/png" in accept or "image/*" in accept:
        return await image_png()
    else:
        return status_code(request, HTTP_406_NOT_ACCEPTABLE)


@get("/image/png", tags=["Images"])
async def image_png() -> Response:
    """Returns a simple PNG image."""
    data = load_resource("images/pig_icon.png")
    return Response(content=data, media_type="image/png")


@get("/image/jpeg", tags=["Images"])
async def image_jpeg() -> Response:
    """Returns a simple JPEG image."""
    data = load_resource("images/jackal.jpg")
    return Response(content=data, media_type="image/jpeg")


@get("/image/webp", tags=["Images"])
async def image_webp() -> Response:
    """Returns a simple WEBP image."""
    data = load_resource("images/wolf_1.webp")
    return Response(content=data, media_type="image/webp")


@get("/image/svg", tags=["Images"])
async def image_svg() -> Response:
    """Returns a simple SVG image."""
    data = load_resource("images/svg_logo.svg")
    return Response(content=data, media_type="image/svg+xml")


@get("/xml", media_type="application/xml", tags=["Response formats"])
async def xml() -> Template:
    """Returns a simple XML document."""
    return Template(template_name="sample.xml")


@get("/json", tags=["Response formats"])
async def a_json_endpoint() -> dict:
    """Returns a simple JSON document."""
    return {
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


# Collect all route handlers
route_handlers = [
    view_landing_page,
    view_html_page,
    view_robots_page,
    view_deny_page,
    view_origin,
    view_uuid,
    view_headers,
    view_user_agent,
    view_get,
    view_anything,
    view_post,
    view_put,
    view_patch,
    view_delete,
    view_gzip_encoded_content,
    view_deflate_encoded_content,
    view_brotli_encoded_content,
    redirect_n_times,
    redirect_to,
    relative_redirect_n_times,
    absolute_redirect_n_times,
    stream_n_messages,
    view_status_code,
    response_headers,
    view_cookies,
    view_forms_post,
    set_cookie,
    set_cookies,
    delete_cookies,
    basic_auth,
    hidden_basic_auth,
    bearer_auth,
    digest_auth_md5,
    digest_auth_nostale,
    digest_auth,
    delay_response,
    drip,
    decode_base64,
    cache,
    etag,
    cache_control,
    encoding,
    random_bytes,
    stream_random_bytes,
    range_request,
    link_page,
    links,
    image,
    image_png,
    image_jpeg,
    image_webp,
    image_svg,
    xml,
    a_json_endpoint,
]

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
    route_handlers=route_handlers,
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
