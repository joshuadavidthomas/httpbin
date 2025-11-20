"""
httpbin.core
~~~~~~~~~~~~

This module provides the core HttpBin experience using FastAPI.
"""

import base64
import json
import os
import random
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from fastapi import (
    FastAPI,
    Request,
    Response,
    Header,
    Query,
    Path as PathParam,
    status,
    Depends,
    HTTPException,
)
from fastapi.responses import (
    JSONResponse,
    HTMLResponse,
    PlainTextResponse,
    StreamingResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from . import filters
from .helpers import (
    get_headers,
    status_code_response,
    get_dict,
    get_request_range,
    check_basic_auth,
    check_digest_auth,
    secure_cookie,
    H,
    ROBOT_TXT,
    ANGRY_ASCII,
    parse_multi_value_header,
    next_stale_after_value,
    digest_challenge_response,
)
from .utils import weighted_choice
from .structures import CaseInsensitiveDict

# Read version
with open(
    os.path.join(os.path.realpath(os.path.dirname(__file__)), "VERSION")
) as version_file:
    version = version_file.read().strip()

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

# Find the correct template folder
tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=tmpl_dir)

# Create FastAPI app
app = FastAPI(
    title="httpbin.org",
    description="A simple HTTP Request & Response Service.<br/><br/><b>Run locally: </b><code>$ docker run -p 80:80 kennethreitz/httpbin</code>",
    version=version,
    contact={
        "name": "Kenneth Reitz",
        "email": "me@kennethreitz.org",
        "url": "https://kennethreitz.org",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


def jsonify(data: dict) -> JSONResponse:
    """Helper to return JSON with trailing newline"""
    content = json.dumps(data, indent=2) + "\n"
    return Response(content=content, media_type="application/json")


# ------
# Routes
# ------


@app.get("/legacy", response_class=HTMLResponse, tags=["Response formats"])
async def view_landing_page(request: Request):
    """Generates Landing Page in legacy layout."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/html", response_class=HTMLResponse, tags=["Response formats"])
async def view_html_page(request: Request):
    """Returns a simple HTML document."""
    return templates.TemplateResponse("moby.html", {"request": request})


@app.get("/robots.txt", response_class=PlainTextResponse, tags=["Response formats"])
async def view_robots_page():
    """Returns some robots.txt rules."""
    return Response(content=ROBOT_TXT, media_type="text/plain")


@app.get("/deny", response_class=PlainTextResponse, tags=["Response formats"])
async def view_deny_page():
    """Returns page denied by robots.txt rules."""
    return Response(content=ANGRY_ASCII, media_type="text/plain")


@app.get("/ip", tags=["Request inspection"])
async def view_origin(request: Request):
    """Returns the requester's IP Address."""
    origin = request.headers.get("X-Forwarded-For", request.client.host if request.client else "")
    return jsonify({"origin": origin})


@app.get("/uuid", tags=["Dynamic data"])
async def view_uuid():
    """Return a UUID4."""
    return jsonify({"uuid": str(uuid.uuid4())})


@app.get("/headers", tags=["Request inspection"])
async def view_headers(request: Request):
    """Return the incoming request's HTTP headers."""
    return jsonify(get_dict(request, 'headers'))


@app.get("/user-agent", tags=["Request inspection"])
async def view_user_agent(request: Request):
    """Return the incoming requests's User-Agent header."""
    headers = get_headers(request)
    return jsonify({"user-agent": headers.get("user-agent", "")})


@app.get("/get", tags=["HTTP Methods"])
async def view_get(request: Request):
    """The request's query parameters."""
    return jsonify(get_dict(request, "url", "args", "headers", "origin"))


@app.api_route(
    "/anything",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Anything"]
)
@app.api_route(
    "/anything/{anything:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Anything"]
)
async def view_anything(request: Request, anything: Optional[str] = None):
    """Returns anything passed in request data."""
    return jsonify(
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


@app.post("/post", tags=["HTTP Methods"])
async def view_post(request: Request):
    """The request's POST parameters."""
    return jsonify(
        get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.put("/put", tags=["HTTP Methods"])
async def view_put(request: Request):
    """The request's PUT parameters."""
    return jsonify(
        get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.patch("/patch", tags=["HTTP Methods"])
async def view_patch(request: Request):
    """The request's PATCH parameters."""
    return jsonify(
        get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.delete("/delete", tags=["HTTP Methods"])
async def view_delete(request: Request):
    """The request's DELETE parameters."""
    return jsonify(
        get_dict(request, "url", "args", "form", "data", "origin", "headers", "files", "json")
    )


@app.get("/gzip", tags=["Response formats"])
async def view_gzip_encoded_content(request: Request):
    """Returns GZip-encoded data."""
    data = get_dict(request, "origin", "headers", method=request.method, gzipped=True)
    content = json.dumps(data, indent=2) + "\n"
    compressed = filters.gzip_compress(content.encode())
    return Response(
        content=compressed,
        media_type="application/json",
        headers={
            "Content-Encoding": "gzip",
            "Content-Length": str(len(compressed))
        }
    )


@app.get("/deflate", tags=["Response formats"])
async def view_deflate_encoded_content(request: Request):
    """Returns Deflate-encoded data."""
    data = get_dict(request, "origin", "headers", method=request.method, deflated=True)
    content = json.dumps(data, indent=2) + "\n"
    compressed = filters.deflate_compress(content.encode())
    return Response(
        content=compressed,
        media_type="application/json",
        headers={
            "Content-Encoding": "deflate",
            "Content-Length": str(len(compressed))
        }
    )


@app.get("/brotli", tags=["Response formats"])
async def view_brotli_encoded_content(request: Request):
    """Returns Brotli-encoded data."""
    data = get_dict(request, "origin", "headers", method=request.method, brotli=True)
    content = json.dumps(data, indent=2) + "\n"
    compressed = filters.brotli_compress(content.encode())
    return Response(
        content=compressed,
        media_type="application/json",
        headers={
            "Content-Encoding": "br",
            "Content-Length": str(len(compressed))
        }
    )


@app.get("/redirect/{n}", tags=["Redirects"])
async def redirect_n_times(n: int = PathParam(..., ge=1), absolute: bool = Query(False)):
    """302 Redirects n times."""
    if n == 1:
        if absolute:
            return RedirectResponse(url="/get", status_code=302)
        return RedirectResponse(url="/get", status_code=302)

    if absolute:
        return RedirectResponse(url=f"/absolute-redirect/{n-1}", status_code=302)
    else:
        return RedirectResponse(url=f"/relative-redirect/{n-1}", status_code=302)


@app.api_route(
    "/redirect-to",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Redirects"]
)
async def redirect_to(
    url: str = Query(..., description="The URL to redirect to"),
    status_code: int = Query(302, ge=300, lt=400, description="The redirect status code")
):
    """302/3XX Redirects to the given URL."""
    return RedirectResponse(url=url, status_code=status_code)


@app.get("/relative-redirect/{n}", tags=["Redirects"])
async def relative_redirect_n_times(n: int = PathParam(..., ge=1)):
    """Relatively 302 Redirects n times."""
    if n == 1:
        return RedirectResponse(url="/get", status_code=302)
    return RedirectResponse(url=f"/relative-redirect/{n-1}", status_code=302)


@app.get("/absolute-redirect/{n}", tags=["Redirects"])
async def absolute_redirect_n_times(n: int = PathParam(..., ge=1)):
    """Absolutely 302 Redirects n times."""
    if n == 1:
        return RedirectResponse(url="/get", status_code=302)
    return RedirectResponse(url=f"/absolute-redirect/{n-1}", status_code=302)


@app.get("/stream/{n}", tags=["Dynamic data"])
async def stream_n_messages(request: Request, n: int = PathParam(..., ge=1, le=100)):
    """Stream n JSON responses"""
    response_data = get_dict(request, "url", "args", "headers", "origin")

    def generate_stream():
        for i in range(min(n, 100)):
            response_data["id"] = i
            yield json.dumps(response_data) + "\n"

    return StreamingResponse(generate_stream(), media_type="application/json")


@app.api_route(
    "/status/{codes}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Status codes"]
)
async def view_status_code(codes: str):
    """Return status code or random status code if more than one are given"""
    if "," not in codes:
        try:
            code = int(codes)
        except ValueError:
            return Response("Invalid status code", status_code=400)
        return status_code_response(code)

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
            return Response("Invalid status code", status_code=400)

    code = weighted_choice(choices)
    return status_code_response(code)


@app.api_route("/response-headers", methods=["GET", "POST"], tags=["Response inspection"])
async def response_headers(request: Request):
    """Returns a set of response headers from the query string."""
    headers_dict = dict(request.query_params)
    response = jsonify(headers_dict)

    # Add custom headers to response
    for key, value in headers_dict.items():
        response.headers[key] = value

    return response


@app.get("/cookies", tags=["Cookies"])
async def view_cookies(request: Request, show_env: Optional[str] = Query(None)):
    """Returns cookie data."""
    cookies = dict(request.cookies)

    if show_env is None:
        for key in ENV_COOKIES:
            cookies.pop(key, None)

    return jsonify({"cookies": cookies})


@app.get("/forms/post", response_class=HTMLResponse, tags=["Response formats"])
async def view_forms_post(request: Request):
    """Simple HTML form."""
    return templates.TemplateResponse("forms-post.html", {"request": request})


@app.get("/cookies/set/{name}/{value}", tags=["Cookies"])
async def set_cookie(name: str, value: str, request: Request):
    """Sets a cookie and redirects to cookie list."""
    response = RedirectResponse(url="/cookies", status_code=302)
    is_secure = request.url.scheme == "https"
    response.set_cookie(key=name, value=value, secure=is_secure)
    return response


@app.get("/cookies/set", tags=["Cookies"])
async def set_cookies(request: Request):
    """Sets cookie(s) as provided by the query string and redirects to cookie list."""
    cookies = dict(request.query_params)
    response = RedirectResponse(url="/cookies", status_code=302)
    is_secure = request.url.scheme == "https"

    for key, value in cookies.items():
        response.set_cookie(key=key, value=value, secure=is_secure)

    return response


@app.get("/cookies/delete", tags=["Cookies"])
async def delete_cookies(request: Request):
    """Deletes cookie(s) as provided by the query string and redirects to cookie list."""
    cookies = dict(request.query_params)
    response = RedirectResponse(url="/cookies", status_code=302)

    for key in cookies.keys():
        response.delete_cookie(key=key)

    return response


@app.get("/basic-auth/{user}/{passwd}", tags=["Auth"])
async def basic_auth(
    request: Request,
    user: str = PathParam(...),
    passwd: str = PathParam(...),
):
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code_response(401)

    return jsonify({"authenticated": True, "user": user})


@app.get("/hidden-basic-auth/{user}/{passwd}", tags=["Auth"])
async def hidden_basic_auth(
    request: Request,
    user: str = PathParam(...),
    passwd: str = PathParam(...),
):
    """Prompts the user for authorization using HTTP Basic Auth."""
    if not check_basic_auth(request, user, passwd):
        return status_code_response(404)

    return jsonify({"authenticated": True, "user": user})


@app.get("/bearer", tags=["Auth"])
async def bearer_auth(authorization: Optional[str] = Header(None)):
    """Prompts the user for authorization using bearer authentication."""
    if not authorization or not authorization.startswith("Bearer "):
        return Response(
            content="",
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization[len("Bearer "):]
    return jsonify({"authenticated": True, "token": token})


@app.get("/digest-auth/{qop}/{user}/{passwd}", tags=["Auth"])
async def digest_auth_md5(
    request: Request,
    response: Response,
    qop: str = PathParam(...),
    user: str = PathParam(...),
    passwd: str = PathParam(...),
):
    """Prompts the user for authorization using Digest Auth."""
    return await digest_auth(request, response, qop, user, passwd, "MD5", "never")


@app.get("/digest-auth/{qop}/{user}/{passwd}/{algorithm}", tags=["Auth"])
async def digest_auth_nostale(
    request: Request,
    response: Response,
    qop: str = PathParam(...),
    user: str = PathParam(...),
    passwd: str = PathParam(...),
    algorithm: str = PathParam(...),
):
    """Prompts the user for authorization using Digest Auth + Algorithm."""
    return await digest_auth(request, response, qop, user, passwd, algorithm, "never")


@app.get("/digest-auth/{qop}/{user}/{passwd}/{algorithm}/{stale_after}", tags=["Auth"])
async def digest_auth(
    request: Request,
    response: Response,
    qop: str = PathParam(...),
    user: str = PathParam(...),
    passwd: str = PathParam(...),
    algorithm: str = PathParam(...),
    stale_after: str = PathParam(...),
    require_cookie: Optional[str] = Query(None, alias="require-cookie"),
):
    """Prompts the user for authorization using Digest Auth + Algorithm."""
    require_cookie_handling = require_cookie and require_cookie.lower() in ("1", "t", "true")

    if algorithm not in ("MD5", "SHA-256", "SHA-512"):
        algorithm = "MD5"

    if qop not in ("auth", "auth-int"):
        qop = None

    authorization = request.headers.get("Authorization")
    credentials = None

    if authorization:
        from werkzeug.http import parse_authorization_header
        credentials = parse_authorization_header(authorization)

    if (
        not authorization
        or not credentials
        or credentials.type.lower() != "digest"
        or (require_cookie_handling and "Cookie" not in request.headers)
    ):
        response = digest_challenge_response(qop, algorithm, request)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("fake", value="fake_value")
        return response

    if require_cookie_handling and request.cookies.get("fake") != "fake_value":
        response = jsonify({"errors": ["missing cookie set on challenge"]})
        response.set_cookie("fake", value="fake_value")
        response.status_code = 403
        return response

    current_nonce = credentials.get("nonce")
    stale_after_value = request.cookies.get("stale_after")

    if (
        request.cookies.get("last_nonce")
        and current_nonce == request.cookies.get("last_nonce")
        or stale_after_value == "0"
    ):
        response = digest_challenge_response(qop, algorithm, request, True)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("last_nonce", value=current_nonce)
        response.set_cookie("fake", value="fake_value")
        return response

    if not check_digest_auth(request, user, passwd):
        response = digest_challenge_response(qop, algorithm, request, False)
        response.set_cookie("stale_after", value=stale_after)
        response.set_cookie("last_nonce", value=current_nonce)
        response.set_cookie("fake", value="fake_value")
        return response

    response = jsonify({"authenticated": True, "user": user})
    response.set_cookie("fake", value="fake_value")

    if stale_after_value:
        response.set_cookie("stale_after", value=next_stale_after_value(stale_after_value))

    return response


@app.api_route("/delay/{delay}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], tags=["Dynamic data"])
async def delay_response(request: Request, delay: float = PathParam(...)):
    """Returns a delayed response (max of 10 seconds)."""
    delay = min(delay, 10)
    time.sleep(delay)

    return jsonify(
        get_dict(request, "url", "args", "form", "data", "origin", "headers", "files")
    )


@app.get("/drip", tags=["Dynamic data"])
async def drip(
    duration: float = Query(2, description="The amount of time (in seconds) over which to drip each byte"),
    numbytes: int = Query(10, description="The number of bytes to respond with"),
    code: int = Query(200, description="The response code that will be returned"),
    delay: float = Query(0, description="The amount of time (in seconds) to delay before responding"),
):
    """Drips data over a duration after an optional initial delay."""
    numbytes = min(numbytes, 10 * 1024 * 1024)  # 10MB limit

    if numbytes <= 0:
        return Response("number of bytes must be positive", status_code=400)

    if delay > 0:
        time.sleep(delay)

    pause = duration / numbytes

    def generate_bytes():
        for i in range(numbytes):
            yield b"*"
            time.sleep(pause)

    return StreamingResponse(
        generate_bytes(),
        media_type="application/octet-stream",
        status_code=code,
        headers={"Content-Length": str(numbytes)},
    )


@app.get("/base64/{value}", tags=["Dynamic data"])
async def decode_base64(value: str):
    """Decodes base64url-encoded string."""
    encoded = value.encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")
        return PlainTextResponse(decoded)
    except Exception:
        return PlainTextResponse("Incorrect Base64 data try: SFRUUEJJTiBpcyBhd2Vzb21l")


@app.get("/cache", tags=["Response inspection"])
async def cache(
    request: Request,
    if_modified_since: Optional[str] = Header(None, alias="If-Modified-Since"),
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    """Returns a 304 if an If-Modified-Since header or If-None-Match is present. Returns the same as a GET otherwise."""
    from werkzeug.http import http_date

    if if_modified_since or if_none_match:
        return status_code_response(304)

    data = get_dict(request, "url", "args", "headers", "origin")
    response = jsonify(data)
    response.headers["Last-Modified"] = http_date()
    response.headers["ETag"] = uuid.uuid4().hex
    return response


@app.get("/etag/{etag}", tags=["Response inspection"])
async def etag(
    request: Request,
    etag: str,
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
    if_match: Optional[str] = Header(None, alias="If-Match"),
):
    """Assumes the resource has the given etag and responds to If-None-Match and If-Match headers appropriately."""
    if_none_match_list = parse_multi_value_header(if_none_match) if if_none_match else []
    if_match_list = parse_multi_value_header(if_match) if if_match else []

    if if_none_match_list:
        if etag in if_none_match_list or "*" in if_none_match_list:
            response = status_code_response(304)
            response.headers["ETag"] = etag
            return response
    elif if_match_list:
        if etag not in if_match_list and "*" not in if_match_list:
            return status_code_response(412)

    # Special cases don't apply, return normal response
    data = get_dict(request, "url", "args", "headers", "origin")
    response = jsonify(data)
    response.headers["ETag"] = etag
    return response


@app.get("/cache/{value}", tags=["Response inspection"])
async def cache_control(request: Request, value: int):
    """Sets a Cache-Control header for n seconds."""
    data = get_dict(request, "url", "args", "headers", "origin")
    response = jsonify(data)
    response.headers["Cache-Control"] = f"public, max-age={value}"
    return response


@app.get("/encoding/utf8", response_class=HTMLResponse, tags=["Response formats"])
async def encoding(request: Request):
    """Returns a UTF-8 encoded body."""
    return templates.TemplateResponse("UTF-8-demo.txt", {"request": request})


@app.get("/bytes/{n}", tags=["Dynamic data"])
async def random_bytes(n: int = PathParam(..., le=102400), seed: Optional[int] = Query(None)):
    """Returns n random bytes generated with given seed"""
    n = min(n, 100 * 1024)  # 100KB limit

    if seed is not None:
        random.seed(seed)

    data = bytearray(random.randint(0, 255) for i in range(n))
    return Response(content=bytes(data), media_type="application/octet-stream")


@app.get("/stream-bytes/{n}", tags=["Dynamic data"])
async def stream_random_bytes(
    n: int = PathParam(..., le=102400),
    seed: Optional[int] = Query(None),
    chunk_size: int = Query(10 * 1024),
):
    """Streams n random bytes generated with given seed, at given chunk size per packet."""
    n = min(n, 100 * 1024)  # 100KB limit

    if seed is not None:
        random.seed(seed)

    chunk_size = max(1, chunk_size)

    def generate_bytes():
        chunks = bytearray()
        for i in range(n):
            chunks.append(random.randint(0, 255))
            if len(chunks) == chunk_size:
                yield bytes(chunks)
                chunks = bytearray()

        if chunks:
            yield bytes(chunks)

    return StreamingResponse(generate_bytes(), media_type="application/octet-stream")


@app.get("/range/{numbytes}", tags=["Dynamic data"])
async def range_request(
    request: Request,
    numbytes: int = PathParam(..., ge=1, le=102400),
    chunk_size: int = Query(10 * 1024),
    duration: float = Query(0),
):
    """Streams n random bytes generated with given seed, at given chunk size per packet."""
    if numbytes <= 0 or numbytes > (100 * 1024):
        return Response(
            content="number of bytes must be in the range (0, 102400]",
            status_code=404,
            headers={
                "ETag": f"range{numbytes}",
                "Accept-Ranges": "bytes"
            }
        )

    chunk_size = max(1, chunk_size)
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
            content="",
            status_code=416,
            headers={
                "ETag": f"range{numbytes}",
                "Accept-Ranges": "bytes",
                "Content-Range": f"bytes */{numbytes}",
                "Content-Length": "0",
            }
        )

    def generate_bytes():
        chunks = bytearray()
        for i in range(first_byte_pos, last_byte_pos + 1):
            # Predictable data generation
            chunks.append(ord("a") + (i % 26))
            if len(chunks) == chunk_size:
                yield bytes(chunks)
                time.sleep(pause_per_byte * chunk_size)
                chunks = bytearray()

        if chunks:
            time.sleep(pause_per_byte * len(chunks))
            yield bytes(chunks)

    content_range = f"bytes {first_byte_pos}-{last_byte_pos}/{numbytes}"
    response_headers = {
        "ETag": f"range{numbytes}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(range_length),
        "Content-Range": content_range,
    }

    status_code = 200 if (first_byte_pos == 0 and last_byte_pos == numbytes - 1) else 206

    return StreamingResponse(
        generate_bytes(),
        media_type="application/octet-stream",
        status_code=status_code,
        headers=response_headers,
    )


@app.get("/links/{n}/{offset}", response_class=HTMLResponse, tags=["Dynamic data"])
async def link_page(n: int = PathParam(..., ge=1, le=200), offset: int = PathParam(..., ge=0)):
    """Generate a page containing n links to other pages which do the same."""
    n = min(max(1, n), 200)  # limit to between 1 and 200 links

    html_parts = ["<html><head><title>Links</title></head><body>"]

    for i in range(n):
        if i == offset:
            html_parts.append(f"{i} ")
        else:
            html_parts.append(f"<a href='/links/{n}/{i}'>{i}</a> ")

    html_parts.append("</body></html>")

    return HTMLResponse("".join(html_parts))


@app.get("/links/{n}", tags=["Dynamic data"])
async def links(n: int = PathParam(..., ge=1, le=200)):
    """Redirect to first links page."""
    return RedirectResponse(url=f"/links/{n}/0", status_code=302)


@app.get("/image", tags=["Images"])
async def image(accept: Optional[str] = Header(None)):
    """Returns a simple image of the type suggest by the Accept header."""
    if not accept:
        return await image_png()  # Default to PNG

    accept = accept.lower()

    if "image/webp" in accept:
        return await image_webp()
    elif "image/svg+xml" in accept:
        return await image_svg()
    elif "image/jpeg" in accept:
        return await image_jpeg()
    elif "image/png" in accept or "image/*" in accept:
        return await image_png()
    else:
        return status_code_response(406)  # Unsupported media type


@app.get("/image/png", tags=["Images"])
async def image_png():
    """Returns a simple PNG image."""
    data = resource("images/pig_icon.png")
    return Response(content=data, media_type="image/png")


@app.get("/image/jpeg", tags=["Images"])
async def image_jpeg():
    """Returns a simple JPEG image."""
    data = resource("images/jackal.jpg")
    return Response(content=data, media_type="image/jpeg")


@app.get("/image/webp", tags=["Images"])
async def image_webp():
    """Returns a simple WEBP image."""
    data = resource("images/wolf_1.webp")
    return Response(content=data, media_type="image/webp")


@app.get("/image/svg", tags=["Images"])
async def image_svg():
    """Returns a simple SVG image."""
    data = resource("images/svg_logo.svg")
    return Response(content=data, media_type="image/svg+xml")


def resource(filename: str) -> bytes:
    """Load a resource file"""
    path = os.path.join(tmpl_dir, filename)
    with open(path, "rb") as f:
        return f.read()


@app.get("/xml", response_class=HTMLResponse, tags=["Response formats"])
async def xml(request: Request):
    """Returns a simple XML document."""
    return templates.TemplateResponse(
        "sample.xml",
        {"request": request},
        media_type="application/xml"
    )


@app.get("/json", tags=["Response formats"])
async def a_json_endpoint():
    """Returns a simple JSON document."""
    return jsonify({
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
    })


# Root endpoint - serves API documentation
@app.get("/", include_in_schema=False)
async def root():
    """Redirect to API documentation"""
    return RedirectResponse(url="/docs", status_code=302)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
