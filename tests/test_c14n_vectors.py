"""
Tests for canonical JSON serialization (json_c14n_v1)

These tests verify exact byte output and SHA256 hashes against fixed test vectors.
This is load-bearing for tamper-evident receipts.
"""

import json
import hashlib
import pytest
import sys
import os

# Add the gateway module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from gateway.app.services.c14n import json_c14n_v1


def load_test_vectors():
    """Load test vectors from JSON file."""
    vector_path = os.path.join(os.path.dirname(__file__), 'canonicalization_vectors.json')
    with open(vector_path, 'r') as f:
        return json.load(f)


class TestCanonicalJSON:
    """Test suite for canonical JSON serialization."""
    
    @pytest.fixture
    def vectors(self):
        """Load test vectors."""
        return load_test_vectors()
    
    def test_exact_bytes(self, vectors):
        """Test that canonicalization produces exact expected bytes."""
        for vector in vectors:
            canonical = json_c14n_v1(vector['input'])
            expected = vector['canonical_json'].encode('utf-8')
            
            assert canonical == expected, (
                f"Mismatch for {vector['description']}:\n"
                f"Expected: {expected!r}\n"
                f"Got: {canonical!r}"
            )
    
    def test_sha256_hashes(self, vectors):
        """Test that canonicalization produces exact expected SHA256 hashes."""
        for vector in vectors:
            canonical = json_c14n_v1(vector['input'])
            sha256_hash = hashlib.sha256(canonical).hexdigest()
            
            assert sha256_hash == vector['sha256'], (
                f"Hash mismatch for {vector['description']}:\n"
                f"Expected: {vector['sha256']}\n"
                f"Got: {sha256_hash}\n"
                f"Canonical: {canonical!r}"
            )
    
    def test_rejects_nan(self):
        """Test that NaN is rejected."""
        with pytest.raises(ValueError, match="NaN and Infinity"):
            json_c14n_v1({"value": float('nan')})
    
    def test_rejects_infinity(self):
        """Test that Infinity is rejected."""
        with pytest.raises(ValueError, match="NaN and Infinity"):
            json_c14n_v1({"value": float('inf')})
    
    def test_rejects_negative_infinity(self):
        """Test that -Infinity is rejected."""
        with pytest.raises(ValueError, match="NaN and Infinity"):
            json_c14n_v1({"value": float('-inf')})
    
    def test_keys_sorted_lexicographically(self):
        """Test that object keys are sorted lexicographically."""
        obj = {"zebra": 1, "apple": 2, "mouse": 3}
        canonical = json_c14n_v1(obj)
        
        # Should be sorted: apple, mouse, zebra
        assert canonical == b'{"apple":2,"mouse":3,"zebra":1}'
    
    def test_array_order_preserved(self):
        """Test that array order is preserved."""
        arr = [5, 3, 8, 1]
        canonical = json_c14n_v1(arr)
        
        # Order should be preserved
        assert canonical == b'[5,3,8,1]'
    
    def test_no_whitespace(self):
        """Test that output contains no whitespace."""
        obj = {"key": "value", "nested": {"a": 1, "b": 2}}
        canonical = json_c14n_v1(obj)
        
        # Should contain no spaces, newlines, or tabs
        assert b' ' not in canonical
        assert b'\n' not in canonical
        assert b'\t' not in canonical
    
    def test_unicode_preserved(self):
        """Test that Unicode characters are preserved (not ASCII-escaped)."""
        obj = {"message": "Hello 世界 🌍"}
        canonical = json_c14n_v1(obj)
        
        # Should contain UTF-8 encoded Unicode, not escaped
        assert "世界".encode('utf-8') in canonical
        assert "🌍".encode('utf-8') in canonical
        assert b'\\u' not in canonical  # No Unicode escapes
    
    def test_determinism(self):
        """Test that same input always produces same output."""
        obj = {"z": "last", "a": "first", "nested": {"b": 2, "a": 1}}
        
        # Call multiple times
        result1 = json_c14n_v1(obj)
        result2 = json_c14n_v1(obj)
        result3 = json_c14n_v1(obj)
        
        # All should be identical
        assert result1 == result2 == result3
    
    def test_nested_sorting(self):
        """Test that nested objects also have sorted keys."""
        obj = {
            "outer_z": {
                "inner_z": 1,
                "inner_a": 2
            },
            "outer_a": {
                "inner_z": 3,
                "inner_a": 4
            }
        }
        canonical = json_c14n_v1(obj)
        
        # Both outer and inner keys should be sorted
        expected = b'{"outer_a":{"inner_a":4,"inner_z":3},"outer_z":{"inner_a":2,"inner_z":1}}'
        assert canonical == expected


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
