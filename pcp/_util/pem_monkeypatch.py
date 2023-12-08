import base64
import io
import re
import sys

from asn1crypto._errors import unwrap
from asn1crypto._types import type_name as _type_name, str_cls, byte_cls
import asn1crypto.pem


def patch(module, name):
    def wrap(f):
        print(f"PATCHING {f} INTO {module}")
        setattr(module, name, f)
        return f
    return wrap


#@patch(asn1crypto.pem, '_unarmor')
def better__unarmor(pem_bytes):
    """
    Convert a PEM-encoded byte string into one or more DER-encoded byte strings

    :param pem_bytes:
        A byte string of the PEM-encoded data

    :raises:
        ValueError - when the pem_bytes do not appear to be PEM-encoded bytes

    :return:
        A generator of 3-element tuples in the format: (object_type, headers,
        der_bytes). The object_type is a unicode string of what is between
        "-----BEGIN " and "-----". Examples include: "CERTIFICATE",
        "PUBLIC KEY", "PRIVATE KEY". The headers is a dict containing any lines
        in the form "Name: Value" that are right after the begin line.
    """

    if not isinstance(pem_bytes, byte_cls):
        raise TypeError(unwrap(
            '''
            pem_bytes must be a byte string, not %s
            ''',
            _type_name(pem_bytes)
        ))

    # Valid states include: "trash", "headers", "body"
    state = 'trash'
    headers = {}
    base64_data = b''
    object_type = None

    found_start = False
    found_end = False

    for line in io.BytesIO(pem_bytes):
        line = re.sub(rb'\r?\n?$', b'', line, count=1)
        if line == b'':
            continue

        if state == "trash":
            # Look for a starting line since some CA cert bundle show the cert
            # into in a parsed format above each PEM block
            type_name_match = re.match(b'^(?:---- |-----)BEGIN ([A-Z0-9 ]+)(?: ----|-----)', line)
            if not type_name_match:
                continue
            object_type = type_name_match.group(1).decode('ascii')

            found_start = True
            state = 'headers'
            continue

        if state == 'headers':
            if line.find(b':') == -1:
                state = 'body'
            else:
                decoded_line = line.decode('ascii')
                name, value = decoded_line.split(':', 1)
                headers[name] = value.strip()
                continue

        if state == 'body':
            if line[0:5] in (b'-----', b'---- '):
                der_bytes = base64.b64decode(base64_data)

                yield (object_type, headers, der_bytes)

                state = 'trash'
                headers = {}
                base64_data = b''
                object_type = None
                found_end = True
                continue

            base64_data += line

    if not found_start or not found_end:
        raise ValueError(unwrap(
            '''
            pem_bytes does not appear to contain PEM-encoded data - no
            BEGIN/END combination found
            '''
        ))
