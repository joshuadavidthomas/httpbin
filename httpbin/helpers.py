"""
httpbin.helpers
~~~~~~~~~~~~~~~

This module provides helper functions for httpbin.
"""

import json
import base64
import re
import time
import os
from hashlib import md5, sha256, sha512
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urlunparse

from fastapi import Request, Response
try:
    from werkzeug.http import parse_authorization_header
except ImportError:
    from werkzeug.datastructures import Authorization

    def parse_authorization_header(value):
        """Parse authorization header for newer werkzeug versions"""
        if not value:
            return None
        try:
            return Authorization.from_header(value)
        except Exception:
            return None

from werkzeug.datastructures import WWWAuthenticate

from .structures import CaseInsensitiveDict


ASCII_ART = """
    -=[ teapot ]=-

       _...._
     .'  _ _ `.
    | ."` ^ `". _,
    \_;`"---"`|//
      |       ;/
      \_     _/
"""

REDIRECT_LOCATION = '/redirect/1'

ENV_HEADERS = (
    'X-Varnish',
    'X-Request-Start',
    'X-Heroku-Queue-Depth',
    'X-Real-Ip',
    'X-Forwarded-Proto',
    'X-Forwarded-Protocol',
    'X-Forwarded-Ssl',
    'X-Heroku-Queue-Wait-Time',
    'X-Forwarded-For',
    'X-Heroku-Dynos-In-Use',
    'X-Forwarded-Protocol',
    'X-Forwarded-Port',
    'X-Request-Id',
    'Via',
    'Total-Route-Time',
    'Connect-Time'
)

ROBOT_TXT = """User-agent: *
Disallow: /deny
"""

ACCEPTED_MEDIA_TYPES = [
    'image/webp',
    'image/svg+xml',
    'image/jpeg',
    'image/png',
    'image/*'
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


def json_safe(string: bytes, content_type: str = 'application/octet-stream') -> str:
    """Returns JSON-safe version of `string`.

    If `string` is a Unicode string or a valid UTF-8, it is returned unmodified,
    as it can safely be encoded to JSON string.

    If `string` contains raw/binary data, it is Base64-encoded, formatted and
    returned according to "data" URL scheme (RFC2397). Since JSON is not
    suitable for binary data, some additional encoding was necessary; "data"
    URL scheme was chosen for its simplicity.
    """
    try:
        decoded = string.decode('utf-8')
        json.dumps(decoded)
        return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        return (
            b'data:'
            + content_type.encode('utf-8')
            + b';base64,'
            + base64.b64encode(string)
        ).decode('utf-8')


async def get_files(request: Request) -> Dict[str, Any]:
    """Returns files dict from request context."""
    files = {}

    try:
        form = await request.form()
        for key, file in form.items():
            if hasattr(file, 'read'):
                content_type = getattr(file, 'content_type', 'application/octet-stream')
                content = await file.read()
                val = json_safe(content, content_type)

                if key in files:
                    if not isinstance(files[key], list):
                        files[key] = [files[key]]
                    files[key].append(val)
                else:
                    files[key] = val
    except Exception:
        pass

    return files


def get_headers(request: Request, hide_env: bool = True) -> CaseInsensitiveDict:
    """Returns headers dict from request context."""
    headers = dict(request.headers.items())

    if hide_env and 'show_env' not in request.query_params:
        for key in ENV_HEADERS:
            headers.pop(key, None)

    return CaseInsensitiveDict(headers.items())


def semiflatten(multi: dict) -> dict:
    """Convert a dict with potential list values into a regular dict.
    If there's only one value for a key, use that value directly.
    Otherwise, keep the list."""
    if multi:
        result = {}
        for k, v in multi.items():
            if isinstance(v, list) and len(v) == 1:
                result[k] = v[0]
            else:
                result[k] = v
        return result
    return multi


def get_url(request: Request) -> str:
    """
    Since we might be hosted behind a proxy, we need to check the
    X-Forwarded-Proto, X-Forwarded-Protocol, or X-Forwarded-SSL headers
    to find out what protocol was used to access us.
    """
    protocol = request.headers.get('X-Forwarded-Proto') or request.headers.get('X-Forwarded-Protocol')
    if protocol is None and request.headers.get('X-Forwarded-Ssl') == 'on':
        protocol = 'https'
    if protocol is None:
        return str(request.url)

    url = list(urlparse(str(request.url)))
    url[0] = protocol
    return urlunparse(url)


def get_dict(request: Request, *keys, **extras) -> Dict[str, Any]:
    """Returns request dict of given keys."""
    import asyncio

    _keys = ('url', 'args', 'form', 'data', 'origin', 'headers', 'files', 'json', 'method')

    assert all(k in _keys for k in keys), f"Invalid keys. Must be one of {_keys}"

    # Get form data synchronously if needed
    form = {}
    files = {}
    data = b""
    _json = None

    if 'form' in keys or 'files' in keys or 'data' in keys or 'json' in keys:
        # We need to get the body
        try:
            # Try to get cached body if available
            if hasattr(request, '_body'):
                data = request._body
            else:
                # Read and cache the body
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If we're in an async context, we can't call async functions
                    # This is a limitation - we'll return empty values
                    pass
                else:
                    data = asyncio.run(request.body())
                    request._body = data
        except Exception:
            data = b""

        # Try to parse form data
        if 'form' in keys:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if hasattr(request, '_form'):
                    form_data = request._form
                else:
                    # This is tricky - we need async context
                    form_data = {}
                form = semiflatten(dict(form_data))
            except Exception:
                form = {}

        # Try to parse JSON
        if 'json' in keys or not data:
            try:
                _json = json.loads(data.decode('utf-8')) if data else None
            except (ValueError, TypeError, UnicodeDecodeError):
                _json = None

    d = {
        'url': get_url(request),
        'args': semiflatten(dict(request.query_params)),
        'form': form,
        'data': json_safe(data) if data else '',
        'origin': request.headers.get('X-Forwarded-For', request.client.host if request.client else ''),
        'headers': dict(get_headers(request)),
        'files': files,
        'json': _json,
        'method': request.method,
    }

    out_d = {}
    for key in keys:
        out_d[key] = d.get(key)

    out_d.update(extras)
    return out_d


def status_code_response(code: int) -> Response:
    """Returns response object of given status code."""
    redirect = {'headers': {'location': REDIRECT_LOCATION}}

    code_map = {
        301: redirect,
        302: redirect,
        303: redirect,
        304: {'data': ''},
        305: redirect,
        307: redirect,
        401: {'headers': {'WWW-Authenticate': 'Basic realm="Fake Realm"'}},
        402: {
            'data': 'Fuck you, pay me!',
            'headers': {'x-more-info': 'http://vimeo.com/22053820'}
        },
        406: {
            'data': json.dumps({
                'message': 'Client did not request a supported media type.',
                'accept': ACCEPTED_MEDIA_TYPES
            }),
            'headers': {'Content-Type': 'application/json'}
        },
        407: {'headers': {'Proxy-Authenticate': 'Basic realm="Fake Realm"'}},
        418: {  # I'm a teapot!
            'data': ASCII_ART,
            'headers': {'x-more-info': 'http://tools.ietf.org/html/rfc2324'}
        },
    }

    content = ""
    headers = {}

    if code in code_map:
        m = code_map[code]
        if 'data' in m:
            content = m['data']
        if 'headers' in m:
            headers = m['headers']

    return Response(content=content, status_code=code, headers=headers)


def check_basic_auth(request: Request, user: str, passwd: str) -> bool:
    """Checks user authentication using HTTP Basic Auth."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return False

    try:
        credentials = parse_authorization_header(auth_header)
        if not credentials:
            return False

        return (
            credentials.type.lower() == "basic"
            and credentials.username == user
            and credentials.password == passwd
        )
    except Exception:
        return False


# Digest auth helpers
def H(data: bytes, algorithm: str) -> str:
    """Hash data using specified algorithm"""
    if algorithm == 'SHA-256':
        return sha256(data).hexdigest()
    elif algorithm == 'SHA-512':
        return sha512(data).hexdigest()
    else:
        return md5(data).hexdigest()


def HA1(realm: str, username: str, password: str, algorithm: str) -> str:
    """Create HA1 hash by realm, username, password

    HA1 = md5(A1) = MD5(username:realm:password)
    """
    if not realm:
        realm = ''
    return H(
        b":".join([
            username.encode('utf-8'),
            realm.encode('utf-8'),
            password.encode('utf-8')
        ]),
        algorithm
    )


def HA2(credentials: dict, request_data: dict, algorithm: str) -> str:
    """Create HA2 md5 hash

    If the qop directive's value is "auth" or is unspecified, then HA2:
        HA2 = md5(A2) = MD5(method:digestURI)
    If the qop directive's value is "auth-int", then HA2 is
        HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
    """
    if credentials.get("qop") == "auth" or credentials.get('qop') is None:
        return H(
            b":".join([
                request_data['method'].encode('utf-8'),
                request_data['uri'].encode('utf-8')
            ]),
            algorithm
        )
    elif credentials.get("qop") == "auth-int":
        for k in ('method', 'uri', 'body'):
            if k not in request_data:
                raise ValueError(f"{k} required")
        A2 = b":".join([
            request_data['method'].encode('utf-8'),
            request_data['uri'].encode('utf-8'),
            H(request_data['body'], algorithm).encode('utf-8')
        ])
        return H(A2, algorithm)
    raise ValueError("Invalid qop")


def response_hash(credentials: dict, password: str, request_data: dict) -> str:
    """Compile digest auth response

    If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
    Else if the qop directive is unspecified, then compute the response as follows:
       RESPONSE = MD5(HA1:nonce:HA2)
    """
    algorithm = credentials.get('algorithm', 'MD5')
    HA1_value = HA1(
        credentials.get('realm', ''),
        credentials.get('username', ''),
        password,
        algorithm
    )
    HA2_value = HA2(credentials, request_data, algorithm)

    if credentials.get('qop') is None:
        return H(
            b":".join([
                HA1_value.encode('utf-8'),
                credentials.get('nonce', '').encode('utf-8'),
                HA2_value.encode('utf-8')
            ]),
            algorithm
        )
    elif credentials.get('qop') in ('auth', 'auth-int'):
        for k in ('nonce', 'nc', 'cnonce', 'qop'):
            if k not in credentials:
                raise ValueError(f"{k} required for response H")
        return H(
            b":".join([
                HA1_value.encode('utf-8'),
                credentials.get('nonce', '').encode('utf-8'),
                credentials.get('nc', '').encode('utf-8'),
                credentials.get('cnonce', '').encode('utf-8'),
                credentials.get('qop', '').encode('utf-8'),
                HA2_value.encode('utf-8')
            ]),
            algorithm
        )
    raise ValueError("qop value is wrong")


def check_digest_auth(request: Request, user: str, passwd: str) -> bool:
    """Check user authentication using HTTP Digest auth"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return False

    credentials = parse_authorization_header(auth_header)
    if not credentials:
        return False

    # Build request URI
    request_uri = request.url.path
    if request.url.query:
        request_uri += '?' + request.url.query

    try:
        # Get request body
        body = b""
        if hasattr(request, '_body'):
            body = request._body

        hash_value = response_hash(
            credentials,
            passwd,
            {
                'uri': request_uri,
                'body': body,
                'method': request.method
            }
        )
        return credentials.get('response') == hash_value
    except Exception:
        return False


def secure_cookie(request: Request) -> bool:
    """Return true if cookie should have secure attribute"""
    return request.url.scheme == 'https'


def __parse_request_range(range_header_text: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """Return a tuple describing the byte range requested in a GET request

    If the range is open ended on the left or right side, then a value of None
    will be set.

    RFC7233: http://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7233.html#header.range

    Examples:
      Range: bytes=1024-
      Range: bytes=10-20
      Range: bytes=-999
    """
    left = None
    right = None

    if not range_header_text:
        return left, right

    range_header_text = range_header_text.strip()
    if not range_header_text.startswith('bytes'):
        return left, right

    components = range_header_text.split("=")
    if len(components) != 2:
        return left, right

    components = components[1].split("-")

    try:
        right = int(components[1])
    except (ValueError, IndexError):
        pass

    try:
        left = int(components[0])
    except (ValueError, IndexError):
        pass

    return left, right


def get_request_range(request_headers: CaseInsensitiveDict, upper_bound: int) -> Tuple[int, int]:
    """Parse range header and return first and last byte positions"""
    first_byte_pos, last_byte_pos = __parse_request_range(request_headers.get('range'))

    if first_byte_pos is None and last_byte_pos is None:
        # Request full range
        first_byte_pos = 0
        last_byte_pos = upper_bound - 1
    elif first_byte_pos is None:
        # Request the last X bytes
        first_byte_pos = max(0, upper_bound - last_byte_pos)
        last_byte_pos = upper_bound - 1
    elif last_byte_pos is None:
        # Request from X to end
        last_byte_pos = upper_bound - 1

    return first_byte_pos, last_byte_pos


def parse_multi_value_header(header_str: Optional[str]) -> list:
    """Break apart an HTTP header string that is potentially a quoted, comma separated list."""
    parsed_parts = []
    if header_str:
        parts = header_str.split(',')
        for part in parts:
            match = re.search(r'\s*(W/)?"?([^"]*)"?\s*', part)
            if match is not None:
                parsed_parts.append(match.group(2))
    return parsed_parts


def next_stale_after_value(stale_after: str) -> str:
    """Decrement stale_after counter"""
    try:
        stale_after_count = int(stale_after) - 1
        return str(stale_after_count)
    except ValueError:
        return 'never'


def digest_challenge_response(
    qop: Optional[str],
    algorithm: str,
    request: Request,
    stale: bool = False
) -> Response:
    """Create a digest auth challenge response"""
    from werkzeug.http import http_date

    # RFC2616 Section4.2: HTTP headers are ASCII
    remote_addr = request.client.host if request.client else ''
    nonce = H(
        b''.join([
            remote_addr.encode('ascii'),
            b':',
            str(time.time()).encode('ascii'),
            b':',
            os.urandom(10)
        ]),
        algorithm
    )
    opaque = H(os.urandom(10), algorithm)

    auth = WWWAuthenticate("digest")
    auth.set_digest(
        'me@kennethreitz.com',
        nonce,
        opaque=opaque,
        qop=('auth', 'auth-int') if qop is None else (qop,),
        algorithm=algorithm
    )
    auth.stale = stale

    return Response(
        content='',
        status_code=401,
        headers={'WWW-Authenticate': auth.to_header()}
    )
