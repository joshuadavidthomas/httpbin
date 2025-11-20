"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""

import base64
import json
import os
import re
import time
from hashlib import md5, sha256, sha512
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from litestar import Request, Response
from werkzeug.datastructures import WWWAuthenticate, Authorization
from werkzeug.http import http_date

from .structures import CaseInsensitiveDict


def parse_authorization_header(value: Optional[str]) -> Optional[Authorization]:
    """Parse an Authorization header.

    This is a simple implementation to replace the removed werkzeug function.
    """
    if not value:
        return None

    try:
        auth_type, auth_info = value.split(None, 1)
    except ValueError:
        return None

    auth_type = auth_type.lower()

    if auth_type == "basic":
        return Authorization({"type": "basic", "string": value})
    elif auth_type == "digest":
        # Parse digest auth parameters
        items = {}
        items["type"] = "digest"

        # Simple parser for digest parameters
        for item in auth_info.split(","):
            item = item.strip()
            if "=" in item:
                key, val = item.split("=", 1)
                key = key.strip()
                val = val.strip()
                # Remove quotes
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                items[key] = val

        return Authorization(items)
    else:
        return Authorization({"type": auth_type})

ASCII_ART = (
    "    -=[ teapot ]=-\n"
    "\n"
    "       _...._\n"
    "     .'  _ _ `.\n"
    '    | ."`  ^ `". _,\n'
    '    \\_;"---"`|//\n'
    "      |       ;/\n"
    "      \\_     _/\n"
    '        `"""`\n'
)

REDIRECT_LOCATION = "/redirect/1"

ENV_HEADERS = (
    "X-Varnish",
    "X-Request-Start",
    "X-Heroku-Queue-Depth",
    "X-Real-Ip",
    "X-Forwarded-Proto",
    "X-Forwarded-Protocol",
    "X-Forwarded-Ssl",
    "X-Heroku-Queue-Wait-Time",
    "X-Forwarded-For",
    "X-Heroku-Dynos-In-Use",
    "X-Forwarded-Protocol",
    "X-Forwarded-Port",
    "X-Request-Id",
    "Via",
    "Total-Route-Time",
    "Connect-Time",
)

ROBOT_TXT = """User-agent: *
Disallow: /deny
"""

ACCEPTED_MEDIA_TYPES = [
    "image/webp",
    "image/svg+xml",
    "image/jpeg",
    "image/png",
    "image/*",
]

ANGRY_ASCII = """
          .-''''''-.
        .' _      _ '.
       /   O      O   \\
      :                :
      |                |
      :       __       :
       \  .-"`  `"-.  /
        '.          .'
          '-......-'
     YOU SHOULDN'T BE HERE
"""


def json_safe(string: bytes, content_type: str = "application/octet-stream") -> str:
    """Returns JSON-safe version of `string`.

    If `string` is a Unicode string or a valid UTF-8, it is returned unmodified,
    as it can safely be encoded to JSON string.

    If `string` contains raw/binary data, it is Base64-encoded, formatted and
    returned according to "data" URL scheme (RFC2397). Since JSON is not
    suitable for binary data, some additional encoding was necessary; "data"
    URL scheme was chosen for its simplicity.
    """
    try:
        decoded = string.decode("utf-8")
        json.dumps(decoded)
        return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        return "".join(
            [
                "data:",
                content_type,
                ";base64,",
                base64.b64encode(string).decode("ascii"),
            ]
        )


async def get_files(request: Request) -> Dict[str, Any]:
    """Returns files dict from request context."""
    files = {}

    form_data = await request.form()
    for key in form_data:
        value = form_data[key]
        # Check if it's a file upload
        if hasattr(value, "read"):
            content_type = getattr(value, "content_type", "application/octet-stream")
            file_content = await value.read() if hasattr(value, "read") else value
            val = json_safe(file_content, content_type)

            if files.get(key):
                if not isinstance(files[key], list):
                    files[key] = [files[key]]
                files[key].append(val)
            else:
                files[key] = val

    return files


def get_headers(request: Request, hide_env: bool = True) -> CaseInsensitiveDict:
    """Returns headers dict from request context."""
    headers = dict(request.headers.items())

    if hide_env and "show_env" not in request.query_params:
        for key in ENV_HEADERS:
            try:
                del headers[key]
            except KeyError:
                pass

    return CaseInsensitiveDict(headers.items())


def semiflatten(multi: Dict) -> Dict:
    """Convert a MultiDict-like object into a regular dict.

    If there are more than one value for a key, the result will have a list of values for the key.
    Otherwise it will have the plain value.
    """
    if not multi:
        return multi

    result = {}
    # Handle query params and form data
    for key, value in multi.items():
        result[key] = value

    return result


def get_url(request: Request) -> str:
    """
    Since we might be hosted behind a proxy, we need to check the
    X-Forwarded-Proto, X-Forwarded-Protocol, or X-Forwarded-SSL headers
    to find out what protocol was used to access us.
    """
    protocol = request.headers.get("X-Forwarded-Proto") or request.headers.get(
        "X-Forwarded-Protocol"
    )
    if protocol is None and request.headers.get("X-Forwarded-Ssl") == "on":
        protocol = "https"
    if protocol is None:
        return str(request.url)

    url = list(urlparse(str(request.url)))
    url[0] = protocol
    return urlunparse(url)


async def get_dict(request: Request, *keys, **extras) -> Dict[str, Any]:
    """Returns request dict of given keys."""
    _keys = ("url", "args", "form", "data", "origin", "headers", "files", "json", "method")

    assert all(k in _keys for k in keys)

    # Get request body
    data = b""
    try:
        data = await request.body()
    except Exception:
        pass

    # Get form data
    form = {}
    try:
        form_data = await request.form()
        form = semiflatten(dict(form_data))
    except Exception:
        pass

    # Try to parse JSON
    _json = None
    try:
        if data:
            _json = json.loads(data.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        pass

    # Get files
    files = {}
    try:
        files = await get_files(request)
    except Exception:
        pass

    d = dict(
        url=get_url(request),
        args=semiflatten(dict(request.query_params)),
        form=form,
        data=json_safe(data),
        origin=request.headers.get(
            "X-Forwarded-For", request.client.host if request.client else ""
        ),
        headers=get_headers(request),
        files=files,
        json=_json,
        method=request.method,
    )

    out_d = {}
    for key in keys:
        out_d[key] = d.get(key)

    out_d.update(extras)
    return out_d


def status_code(request: Request, code: int) -> Response:
    """Returns response object of given status code."""
    redirect = dict(headers=dict(location=REDIRECT_LOCATION))

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: dict(data=""),
        305: redirect,
        307: redirect,
        401: dict(headers={"WWW-Authenticate": 'Basic realm="Fake Realm"'}),
        402: dict(
            data="Fuck you, pay me!",
            headers={"x-more-info": "http://vimeo.com/22053820"},
        ),
        406: dict(
            data=json.dumps(
                {
                    "message": "Client did not request a supported media type.",
                    "accept": ACCEPTED_MEDIA_TYPES,
                }
            ),
            headers={"Content-Type": "application/json"},
        ),
        407: dict(headers={"Proxy-Authenticate": 'Basic realm="Fake Realm"'}),
        418: dict(  # I'm a teapot!
            data=ASCII_ART, headers={"x-more-info": "http://tools.ietf.org/html/rfc2324"}
        ),
    }

    response_data = b""
    response_headers = {}

    if code in code_map:
        m = code_map[code]
        if "data" in m:
            response_data = m["data"].encode() if isinstance(m["data"], str) else m["data"]
        if "headers" in m:
            response_headers = m["headers"]

    return Response(content=response_data, status_code=code, headers=response_headers)


def check_basic_auth(request: Request, user: str, passwd: str) -> bool:
    """Checks user authentication using HTTP Basic Auth."""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Basic "):
        return False

    try:
        # Decode base64 credentials
        encoded_credentials = auth_header[6:]  # Remove "Basic "
        decoded = base64.b64decode(encoded_credentials).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username == user and password == passwd
    except Exception:
        return False


# Digest auth helpers
# qop is a quality of protection


def H(data: bytes, algorithm: str) -> str:
    """Hash function for digest auth."""
    if algorithm == "SHA-256":
        return sha256(data).hexdigest()
    elif algorithm == "SHA-512":
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()


def HA1(realm: str, username: str, password: str, algorithm: str) -> str:
    """Create HA1 hash by realm, username, password

    HA1 = md5(A1) = MD5(username:realm:password)
    """
    if not realm:
        realm = ""
    return H(
        b":".join(
            [username.encode("utf-8"), realm.encode("utf-8"), password.encode("utf-8")]
        ),
        algorithm,
    )


def HA2(credentials: Any, request_dict: Dict[str, str], algorithm: str) -> str:
    """Create HA2 md5 hash

    If the qop directive's value is "auth" or is unspecified, then HA2:
        HA2 = md5(A2) = MD5(method:digestURI)
    If the qop directive's value is "auth-int" , then HA2 is
        HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
    """
    if credentials.get("qop") == "auth" or credentials.get("qop") is None:
        return H(
            b":".join(
                [
                    request_dict["method"].encode("utf-8"),
                    request_dict["uri"].encode("utf-8"),
                ]
            ),
            algorithm,
        )
    elif credentials.get("qop") == "auth-int":
        for k in "method", "uri", "body":
            if k not in request_dict:
                raise ValueError(f"{k} required")
        A2 = b":".join(
            [
                request_dict["method"].encode("utf-8"),
                request_dict["uri"].encode("utf-8"),
                H(request_dict["body"], algorithm).encode("utf-8"),
            ]
        )
        return H(A2, algorithm)
    raise ValueError("Invalid qop value")


def response(credentials: Any, password: str, request_dict: Dict[str, Any]) -> str:
    """Compile digest auth response

    If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
    Else if the qop directive is unspecified, then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:HA2)

    Arguments:
    - `credentials`: credentials dict
    - `password`: request user password
    - `request_dict`: request dict
    """
    algorithm = credentials.get("algorithm")
    HA1_value = HA1(
        credentials.get("realm", ""),
        credentials.get("username", ""),
        password,
        algorithm,
    )
    HA2_value = HA2(credentials, request_dict, algorithm)

    if credentials.get("qop") is None:
        response_hash = H(
            b":".join(
                [
                    HA1_value.encode("utf-8"),
                    credentials.get("nonce", "").encode("utf-8"),
                    HA2_value.encode("utf-8"),
                ]
            ),
            algorithm,
        )
    elif credentials.get("qop") == "auth" or credentials.get("qop") == "auth-int":
        for k in "nonce", "nc", "cnonce", "qop":
            if k not in credentials:
                raise ValueError(f"{k} required for response H")
        response_hash = H(
            b":".join(
                [
                    HA1_value.encode("utf-8"),
                    credentials.get("nonce", "").encode("utf-8"),
                    credentials.get("nc", "").encode("utf-8"),
                    credentials.get("cnonce", "").encode("utf-8"),
                    credentials.get("qop", "").encode("utf-8"),
                    HA2_value.encode("utf-8"),
                ]
            ),
            algorithm,
        )
    else:
        raise ValueError("qop value are wrong")

    return response_hash


async def check_digest_auth(request: Request, user: str, passwd: str) -> bool:
    """Check user authentication using HTTP Digest auth"""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return False

    credentials = parse_authorization_header(auth_header)
    if not credentials:
        return False

    # Build request URI
    request_uri = str(request.url.path)
    if request.url.query:
        request_uri += "?" + str(request.url.query)

    # Get request body
    body = b""
    try:
        body = await request.body()
    except Exception:
        pass

    response_hash = response(
        credentials,
        passwd,
        dict(uri=request_uri, body=body, method=request.method),
    )

    return credentials.get("response") == response_hash


def secure_cookie(request: Request) -> bool:
    """Return true if cookie should have secure attribute"""
    # Check if request is over HTTPS
    proto = request.headers.get("X-Forwarded-Proto", "")
    if proto == "https":
        return True

    # Check URL scheme
    return str(request.url.scheme) == "https"


def __parse_request_range(range_header_text: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """Return a tuple describing the byte range requested in a GET request

    If the range is open ended on the left or right side, then a value of None
    will be set.

    RFC7233: http://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7233.html#header.range

    Examples:
      Range : bytes=1024-
      Range : bytes=10-20
      Range : bytes=-999
    """
    left = None
    right = None

    if not range_header_text:
        return left, right

    range_header_text = range_header_text.strip()
    if not range_header_text.startswith("bytes"):
        return left, right

    components = range_header_text.split("=")
    if len(components) != 2:
        return left, right

    components = components[1].split("-")

    try:
        right = int(components[1])
    except Exception:
        pass

    try:
        left = int(components[0])
    except Exception:
        pass

    return left, right


def get_request_range(
    request_headers: CaseInsensitiveDict, upper_bound: int
) -> Tuple[int, int]:
    """Parse Range header and return first and last byte positions."""
    first_byte_pos, last_byte_pos = __parse_request_range(
        request_headers.get("range")
    )

    if first_byte_pos is None and last_byte_pos is None:
        # Request full range
        first_byte_pos = 0
        last_byte_pos = upper_bound - 1
    elif first_byte_pos is None:
        # Request the last X bytes
        first_byte_pos = max(0, upper_bound - last_byte_pos)
        last_byte_pos = upper_bound - 1
    elif last_byte_pos is None:
        # Request from byte X to end
        last_byte_pos = upper_bound - 1

    return first_byte_pos, last_byte_pos


def parse_multi_value_header(header_str: Optional[str]) -> list:
    """Break apart an HTTP header string that is potentially a quoted, comma separated list."""
    parsed_parts = []
    if header_str:
        parts = header_str.split(",")
        for part in parts:
            match = re.search(r'\s*(W/)?"?([^"]*)"?\s*', part)
            if match is not None:
                parsed_parts.append(match.group(2))
    return parsed_parts


def next_stale_after_value(stale_after: str) -> str:
    """Decrement stale_after counter."""
    try:
        stale_after_count = int(stale_after) - 1
        return str(stale_after_count)
    except ValueError:
        return "never"


def digest_challenge_response(
    request: Request, qop: Optional[str], algorithm: str, stale: bool = False
) -> Response:
    """Generate a digest auth challenge response."""
    # RFC2616 Section4.2: HTTP headers are ASCII
    remote_addr = request.client.host if request.client else ""
    nonce = H(
        b"".join(
            [
                remote_addr.encode("ascii"),
                b":",
                str(time.time()).encode("ascii"),
                b":",
                os.urandom(10),
            ]
        ),
        algorithm,
    )
    opaque = H(os.urandom(10), algorithm)

    auth = WWWAuthenticate("digest")
    auth.set_digest(
        "me@kennethreitz.com",
        nonce,
        opaque=opaque,
        qop=("auth", "auth-int") if qop is None else (qop,),
        algorithm=algorithm,
    )
    auth.stale = stale

    return Response(
        content=b"", status_code=401, headers={"WWW-Authenticate": auth.to_header()}
    )
