"""
Tests for HALO hash chain (halo_v1)

These tests verify the HALO chain computation and verification with fixed test vectors.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from gateway.app.services.halo import compute_halo_chain, verify_halo_chain


class TestHALOChain:
    """Test suite for HALO hash chain."""
    
    @pytest.fixture
    def sample_packet_approved(self):
        """Sample packet for an approved transaction."""
        return {
            "transaction_id": "tx_001",
            "gateway_timestamp_utc": "2024-01-01T00:00:00Z",
            "environment": "production",
            "client_id": "client_abc",
            "intent_manifest": "chat_completion",
            "feature_tag": "gpt4",
            "user_ref": "user_123",
            "prompt_hash": "sha256:abcd1234",
            "rag_hash": "sha256:efgh5678",
            "multimodal_hash": None,
            "policy_receipt_subset": {
                "policy_version": "v1.0",
                "approved": True
            },
            "model_fingerprint": "gpt-4-0613",
            "param_snapshot": {"temperature": 0.7, "max_tokens": 1000},
            "output_hash": "sha256:ijkl9012",
            "token_usage": {"prompt": 50, "completion": 100},
            "latency_ms": 1234
        }
    
    @pytest.fixture
    def sample_packet_denied(self):
        """Sample packet for a denied transaction."""
        return {
            "transaction_id": "tx_002",
            "gateway_timestamp_utc": "2024-01-01T00:01:00Z",
            "environment": "production",
            "client_id": "client_xyz",
            "intent_manifest": "chat_completion",
            "feature_tag": "gpt4",
            "user_ref": "user_456",
            "prompt_hash": "sha256:mnop3456",
            "rag_hash": None,
            "multimodal_hash": None,
            "policy_receipt_subset": {
                "policy_version": "v1.0",
                "approved": False,
                "reason": "quota_exceeded"
            },
            "model_fingerprint": "gpt-4-0613",
            "param_snapshot": {"temperature": 0.7},
            "output_hash": None,  # Null because denied
            "token_usage": None,
            "latency_ms": 45
        }
    
    def test_compute_chain_structure(self, sample_packet_approved):
        """Test that compute_halo_chain returns correct structure."""
        chain = compute_halo_chain(sample_packet_approved)
        
        # Check all required keys exist
        assert "block_1" in chain
        assert "block_2" in chain
        assert "block_3" in chain
        assert "block_4" in chain
        assert "final_hash" in chain
        
        # Check format (should be "sha256:<hex>")
        for key, value in chain.items():
            assert value.startswith("sha256:"), f"{key} should start with 'sha256:'"
            assert len(value) == 71, f"{key} should be 'sha256:' + 64 hex chars"
    
    def test_chain_determinism(self, sample_packet_approved):
        """Test that same input produces same chain."""
        chain1 = compute_halo_chain(sample_packet_approved)
        chain2 = compute_halo_chain(sample_packet_approved)
        chain3 = compute_halo_chain(sample_packet_approved)
        
        assert chain1 == chain2 == chain3
    
    def test_chain_uniqueness(self, sample_packet_approved, sample_packet_denied):
        """Test that different inputs produce different chains."""
        chain1 = compute_halo_chain(sample_packet_approved)
        chain2 = compute_halo_chain(sample_packet_denied)
        
        # Chains should be different
        assert chain1 != chain2
        
        # At least block_1 should differ (different transaction_id)
        assert chain1["block_1"] != chain2["block_1"]
    
    def test_chain_chaining(self, sample_packet_approved):
        """Test that blocks are properly chained (changing early block affects later blocks)."""
        # Compute original chain
        original_chain = compute_halo_chain(sample_packet_approved)
        
        # Modify transaction_id (affects block_1)
        modified_packet = sample_packet_approved.copy()
        modified_packet["transaction_id"] = "tx_modified"
        modified_chain = compute_halo_chain(modified_packet)
        
        # All blocks should differ because of chaining
        assert original_chain["block_1"] != modified_chain["block_1"]
        assert original_chain["block_2"] != modified_chain["block_2"]
        assert original_chain["block_3"] != modified_chain["block_3"]
        assert original_chain["block_4"] != modified_chain["block_4"]
        assert original_chain["final_hash"] != modified_chain["final_hash"]
    
    def test_verify_valid_packet(self, sample_packet_approved):
        """Test verification of a valid packet."""
        # Compute chain and add to packet
        packet_with_chain = sample_packet_approved.copy()
        packet_with_chain["halo_chain"] = compute_halo_chain(sample_packet_approved)
        
        # Verify
        report = verify_halo_chain(packet_with_chain)
        
        assert report["valid"] is True
        assert len(report["failures"]) == 0
        assert len(report["verified_blocks"]) == 5
    
    def test_verify_tampered_packet(self, sample_packet_approved):
        """Test verification detects tampering."""
        # Create valid packet with chain
        packet_with_chain = sample_packet_approved.copy()
        packet_with_chain["halo_chain"] = compute_halo_chain(sample_packet_approved)
        
        # Tamper with the data
        packet_with_chain["transaction_id"] = "tx_tampered"
        
        # Verify should fail
        report = verify_halo_chain(packet_with_chain)
        
        assert report["valid"] is False
        assert len(report["failures"]) > 0
        assert "block_1" in report["failures"][0]  # First block should fail
    
    def test_verify_tampered_chain(self, sample_packet_approved):
        """Test verification detects direct chain tampering."""
        # Create valid packet with chain
        packet_with_chain = sample_packet_approved.copy()
        packet_with_chain["halo_chain"] = compute_halo_chain(sample_packet_approved)
        
        # Tamper with the chain itself
        packet_with_chain["halo_chain"]["block_1"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        
        # Verify should fail
        report = verify_halo_chain(packet_with_chain)
        
        assert report["valid"] is False
        assert len(report["failures"]) > 0
    
    def test_verify_missing_chain(self, sample_packet_approved):
        """Test verification handles missing chain gracefully."""
        # Packet without chain
        report = verify_halo_chain(sample_packet_approved)
        
        assert report["valid"] is False
        assert "Missing halo_chain" in report["failures"][0]
    
    def test_denied_transaction_chain(self, sample_packet_denied):
        """Test that denied transactions (with null output_hash) still produce valid chains."""
        chain = compute_halo_chain(sample_packet_denied)
        
        # Should still have all blocks
        assert "block_1" in chain
        assert "block_2" in chain
        assert "block_3" in chain
        assert "block_4" in chain
        assert "final_hash" in chain
        
        # Add to packet and verify
        packet_with_chain = sample_packet_denied.copy()
        packet_with_chain["halo_chain"] = chain
        
        report = verify_halo_chain(packet_with_chain)
        assert report["valid"] is True
    
    def test_fixed_vector_1(self):
        """Test against a fixed vector for regression testing."""
        # Fixed input
        packet = {
            "transaction_id": "tx_fixed_001",
            "gateway_timestamp_utc": "2024-01-01T12:00:00Z",
            "environment": "test",
            "client_id": "test_client",
            "intent_manifest": "test",
            "feature_tag": "test",
            "user_ref": "test_user",
            "prompt_hash": "sha256:test1",
            "rag_hash": "sha256:test2",
            "multimodal_hash": "sha256:test3",
            "policy_receipt_subset": {"version": "1.0"},
            "model_fingerprint": "test-model",
            "param_snapshot": {"temp": 1.0},
            "output_hash": "sha256:test_output",
            "token_usage": {"total": 100},
            "latency_ms": 500
        }
        
        # Compute chain
        chain = compute_halo_chain(packet)
        
        # These hashes should be stable
        # If the canonicalization or hashing changes, these will fail (intentionally)
        assert chain["block_1"] == "sha256:a829d4a9a3a49b7390e6f5149931ca83d3dbc4d6dd7aeaa4c7dc57bd127078c5"
        assert chain["block_2"] == "sha256:0ae02a0cb38b0453aa865829c5f4c1885ed1bb91ce03e51394e0ae2fe7bc3123"
        assert chain["block_3"] == "sha256:f4ea85c8ccd13e606dfef1d9e6d870c0df17dad1954337a12050fa1a71291c9b"
        assert chain["block_4"] == "sha256:9eb87a9ca61bf09fb0b32cdd463e6422e699e70c3c6c8b2c07fdf40383b56645"
        assert chain["final_hash"] == "sha256:b1874278818dac3f07bc0af4bf368c63825da7c5961ea7a5e6acec635765cc64"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
