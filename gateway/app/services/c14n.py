"""
Canonical JSON serialization (json_c14n_v1)

This module implements deterministic JSON canonicalization for tamper-evident receipts.

Rules:
- UTF-8 encoding
- Objects: keys sorted lexicographically
- Arrays: preserve order
- No whitespace
- Reject NaN/Infinity
- Stable encoding for strings
"""

import json
import math
from typing import Any


def json_c14n_v1(obj: Any) -> bytes:
    """
    Canonicalize a Python object to deterministic JSON bytes.
    
    Args:
        obj: Python object (dict, list, str, int, float, bool, None)
        
    Returns:
        bytes: Canonical JSON representation
        
    Raises:
        ValueError: If object contains NaN or Infinity
    """
    # First, validate no NaN/Infinity in the structure
    _validate_no_special_floats(obj)
    
    # Use json.dumps with specific settings for canonicalization
    canonical_str = json.dumps(
        obj,
        ensure_ascii=False,  # Allow Unicode characters
        sort_keys=True,      # Sort object keys lexicographically
        separators=(',', ':'),  # No whitespace
        allow_nan=False      # Reject NaN/Infinity
    )
    
    # Encode to UTF-8 bytes
    return canonical_str.encode('utf-8')


def _validate_no_special_floats(obj: Any) -> None:
    """
    Recursively validate that no NaN or Infinity exists in the structure.
    
    Args:
        obj: Python object to validate
        
    Raises:
        ValueError: If NaN or Infinity is found
    """
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("NaN and Infinity are not allowed in canonical JSON")
    elif isinstance(obj, dict):
        for value in obj.values():
            _validate_no_special_floats(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_no_special_floats(item)
