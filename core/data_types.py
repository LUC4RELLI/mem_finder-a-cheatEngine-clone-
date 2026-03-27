"""
Data type definitions for memory scanning and editing.
"""
from __future__ import annotations
import struct
from enum import Enum, auto
from typing import Any

import numpy as np


class DataType(Enum):
    INT8       = auto()
    INT16      = auto()
    INT32      = auto()
    INT64      = auto()
    UINT8      = auto()
    UINT16     = auto()
    UINT32     = auto()
    UINT64     = auto()
    FLOAT32    = auto()
    FLOAT64    = auto()
    BOOL       = auto()
    STRING_ASCII = auto()
    BYTE_ARRAY = auto()


# Metadata for each DataType: (display_name, struct_fmt, numpy_dtype, size_bytes)
# STRING_ASCII and BYTE_ARRAY have variable length — size is None.
_TYPE_META: dict[DataType, tuple[str, str | None, Any, int | None]] = {
    DataType.INT8:        ("Int8 (1 byte)",    "<b",  np.int8,    1),
    DataType.INT16:       ("Int16 (2 bytes)",  "<h",  np.int16,   2),
    DataType.INT32:       ("Int32 (4 bytes)",  "<i",  np.int32,   4),
    DataType.INT64:       ("Int64 (8 bytes)",  "<q",  np.int64,   8),
    DataType.UINT8:       ("UInt8 (1 byte)",   "<B",  np.uint8,   1),
    DataType.UINT16:      ("UInt16 (2 bytes)", "<H",  np.uint16,  2),
    DataType.UINT32:      ("UInt32 (4 bytes)", "<I",  np.uint32,  4),
    DataType.UINT64:      ("UInt64 (8 bytes)", "<Q",  np.uint64,  8),
    DataType.FLOAT32:     ("Float (4 bytes)",  "<f",  np.float32, 4),
    DataType.FLOAT64:     ("Double (8 bytes)", "<d",  np.float64, 8),
    DataType.BOOL:        ("Bool (1 byte)",    "<?",  np.bool_,   1),
    DataType.STRING_ASCII:("String ASCII",     None,  None,       None),
    DataType.BYTE_ARRAY:  ("Byte Array",       None,  None,       None),
}


def display_name(dt: DataType) -> str:
    return _TYPE_META[dt][0]


def struct_fmt(dt: DataType) -> str | None:
    return _TYPE_META[dt][1]


def numpy_dtype(dt: DataType) -> Any:
    return _TYPE_META[dt][2]


def type_size(dt: DataType) -> int | None:
    """Returns byte size, or None for variable-length types."""
    return _TYPE_META[dt][3]


def is_variable_length(dt: DataType) -> bool:
    return _TYPE_META[dt][3] is None


def pack(dt: DataType, value: Any) -> bytes:
    """Pack a Python value into bytes according to the given DataType."""
    if dt == DataType.STRING_ASCII:
        if isinstance(value, str):
            return value.encode("ascii", errors="replace")
        return bytes(value)
    if dt == DataType.BYTE_ARRAY:
        if isinstance(value, str):
            # Accept space-separated hex like "DE AD BE EF" or "DEADBEEF"
            cleaned = value.replace(" ", "")
            return bytes.fromhex(cleaned)
        return bytes(value)
    fmt = struct_fmt(dt)
    if fmt is None:
        raise ValueError(f"Cannot pack type {dt}")
    if dt == DataType.BOOL:
        value = bool(value)
    elif dt in (DataType.FLOAT32, DataType.FLOAT64):
        value = float(value)
    else:
        value = int(value)
    return struct.pack(fmt, value)


def unpack(dt: DataType, data: bytes) -> Any:
    """Unpack bytes into a Python value according to the given DataType."""
    if dt == DataType.STRING_ASCII:
        return data.decode("ascii", errors="replace").rstrip("\x00")
    if dt == DataType.BYTE_ARRAY:
        return " ".join(f"{b:02X}" for b in data)
    fmt = struct_fmt(dt)
    if fmt is None:
        raise ValueError(f"Cannot unpack type {dt}")
    size = type_size(dt)
    if len(data) < size:
        raise ValueError(f"Not enough bytes: need {size}, got {len(data)}")
    return struct.unpack(fmt, data[:size])[0]


def format_value(dt: DataType, value: Any) -> str:
    """Format a value for display."""
    if dt == DataType.FLOAT32:
        return f"{value:.6g}"
    if dt == DataType.FLOAT64:
        return f"{value:.10g}"
    if dt == DataType.BOOL:
        return "True" if value else "False"
    if dt in (DataType.STRING_ASCII, DataType.BYTE_ARRAY):
        return str(value)
    return str(value)


ALL_TYPES: list[DataType] = list(DataType)
NUMERIC_TYPES: list[DataType] = [
    DataType.INT8, DataType.INT16, DataType.INT32, DataType.INT64,
    DataType.UINT8, DataType.UINT16, DataType.UINT32, DataType.UINT64,
    DataType.FLOAT32, DataType.FLOAT64, DataType.BOOL,
]
