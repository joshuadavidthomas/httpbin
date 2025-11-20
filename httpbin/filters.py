"""
httpbin.filters
~~~~~~~~~~~~~~~

This module provides response compression functions.
"""

import gzip as gzip_module
import zlib
import brotli


def gzip_compress(data: bytes) -> bytes:
    """GZip compress data"""
    return gzip_module.compress(data, compresslevel=4)


def deflate_compress(data: bytes) -> bytes:
    """Deflate compress data"""
    compressor = zlib.compressobj()
    compressed = compressor.compress(data)
    compressed += compressor.flush()
    return compressed


def brotli_compress(data: bytes) -> bytes:
    """Brotli compress data"""
    return brotli.compress(data)
