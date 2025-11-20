"""
httpbin.filters
~~~~~~~~~~~~~~~

This module provides response filter functions for compression.
"""

import gzip as gzip_module
import zlib
from decimal import Decimal
from time import time as now

import brotli

from litestar import Response


def gzip_response(response: Response) -> Response:
    """GZip compress a Litestar Response."""
    if isinstance(response.content, (str, bytes)):
        content = response.content.encode() if isinstance(response.content, str) else response.content

        # Compress the content
        compressed = gzip_module.compress(content, compresslevel=4)

        # Update response
        response.content = compressed
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(len(compressed))

    return response


def deflate_response(response: Response) -> Response:
    """Deflate compress a Litestar Response."""
    if isinstance(response.content, (str, bytes)):
        content = response.content.encode() if isinstance(response.content, str) else response.content

        # Compress the content
        deflater = zlib.compressobj()
        compressed = deflater.compress(content)
        compressed += deflater.flush()

        # Update response
        response.content = compressed
        response.headers["Content-Encoding"] = "deflate"
        response.headers["Content-Length"] = str(len(compressed))

    return response


def brotli_response(response: Response) -> Response:
    """Brotli compress a Litestar Response."""
    if isinstance(response.content, (str, bytes)):
        content = response.content.encode() if isinstance(response.content, str) else response.content

        # Compress the content
        compressed = brotli.compress(content)

        # Update response
        response.content = compressed
        response.headers["Content-Encoding"] = "br"
        response.headers["Content-Length"] = str(len(compressed))

    return response
