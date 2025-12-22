#!/usr/bin/env python3
"""
CE-CMS Decentralized Identity (DID) Verification Service
Implements DID-based identity verification and credential management
"""

import json
import time
import logging
import hashlib
import jwt
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from cryptography.fernet import Fernet
import base64
import uuid

logger = logging.getLogger(__name__)

class DIDVerificationService:
    """Decentralized Identity verification and management service"""
    
    def __init__(self):
        # DID infrastructure
        self.did_registry = {}  # Device ID -> DID document
        self.credential_store = {}  # Verifiable credentials
        self.verification_history = deque(maxlen=10000)
        
        # Cryptographic components
        self.signing_key = self._generate_signing_key()
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Trust framework
        self.trust_levels = {
            "verified": 1.0,
            "trusted": 0.8,
            "authenticated": 0.6,
            "unverified": 0.2,
            "suspicious": 0.0
        }
        
        # Device fingerprinting
        self.device_fingerprints = {}
        self.behavioral_profiles = defaultdict(dict)
        
        # Blockchain simulation (simplified)
        self.blockchain_ledger = []
        self.pending_transactions = []
        
        # Statistics
        self.stats = {
            "total_verifications": 0,
            "successful_verifications": 0,
            "failed_verifications": 0,
            "credentials_issued": 0,
            "revoked_credentials": 0
        }
        
    def _generate_signing_key(self):
        """Generate signing key for JWT tokens"""
        return base64.b64encode(b"ce_cms_secret_key_" + str(uuid.uuid4()).encode()).decode()
    
    def create_did_document(self, device_id, device_info):
        """Create a DID document for a device"""
        try:
            # Generate unique DID
            did = f"did:ce-cms:{hashlib.sha256(device_id.encode()).hexdigest()[:32]}"
            
            # Create device fingerprint
            fingerprint = self._generate_device_fingerprint(device_info)
            
            # Create DID document
            did_document = {
                "id": did,
                "created": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat(),
                "publicKey": [{
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": did,
                    "publicKeyBase58": base64.b64encode(self.signing_key.encode()).decode()
                }],
                "authentication": [f"{did}#key-1"],
                "service": [{
                    "id": f"{did}#ce-cms-service",
                    "type": "CE-CMS-Security",
                    "serviceEndpoint": "https://ce-cms.example.com/api"
                }],
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "verificationMethod": f"{did}#key-1",
                    "proofPurpose": "assertionMethod"
                },
                "device_fingerprint": fingerprint,
                "trust_level": "authenticated"
            }
            
            # Store in registry
            self.did_registry[device_id] = did_document
            self.device_fingerprints[device_id] = fingerprint
            
            # Add to blockchain ledger (simplified)
            self._add_to_blockchain({
                "type": "did_creation",
                "did": did,
                "device_id": device_id,
                "timestamp": time.time()
            })
            
            logger.info(f"Created DID document for device {device_id}")
            return did_document
            
        except Exception as e:
            logger.error(f"DID creation error: {e}")
            return None
    
    def _generate_device_fingerprint(self, device_info):
        """Generate unique device fingerprint"""
        fingerprint_data = {
            "device_type": device_info.get("device_type", "unknown"),
            "firmware_version": device_info.get("firmware_version", "1.0.0"),
            "hardware_id": device_info.get("hardware_id", "unknown"),
            "capabilities": device_info.get("capabilities", []),
            "creation_time": time.time()
        }
        
        # Create hash-based fingerprint
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return {
            "hash": fingerprint_hash,
            "components": fingerprint_data,
            "created": datetime.now(timezone.utc).isoformat()
        }
    
    def verify_device_identity(self, device_id, device_info):
        """Verify device identity using DID and credentials"""
        try:
            verification_start = time.time()
            
            # Check if DID exists
            if device_id not in self.did_registry:
                # Create new DID for unknown device
                did_document = self.create_did_document(device_id, device_info)
                if not did_document:
                    return self._verification_failed(device_id, "did_creation_failed")
            else:
                did_document = self.did_registry[device_id]
            
            # Verify device fingerprint
            fingerprint_result = self._verify_device_fingerprint(device_id, device_info)
            
            # Check for behavioral consistency
            behavioral_result = self._verify_behavioral_consistency(device_id, device_info)
            
            # Verify credentials
            credential_result = self._verify_device_credentials(device_id)
            
            # Calculate overall trust score
            trust_score = self._calculate_trust_score([
                fingerprint_result, behavioral_result, credential_result
            ])
            
            # Determine verification status
            verification_status = self._determine_verification_status(trust_score)
            
            # Update behavioral profile
            self._update_behavioral_profile(device_id, device_info, trust_score)
            
            # Create verification record
            verification_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "device_id": device_id,
                "did": did_document["id"],
                "verification_status": verification_status,
                "trust_score": trust_score,
                "fingerprint_match": fingerprint_result["match"],
                "behavioral_consistency": behavioral_result["consistent"],
                "credential_valid": credential_result["valid"],
                "processing_time_ms": round((time.time() - verification_start) * 1000, 2)
            }
            
            self.verification_history.append(verification_record)
            
            # Update statistics
            self.stats["total_verifications"] += 1
            if verification_status in ["verified", "trusted"]:
                self.stats["successful_verifications"] += 1
            else:
                self.stats["failed_verifications"] += 1
            
            # Log significant verification events
            if verification_status in ["suspicious", "unverified"]:
                self._log_verification_event(verification_record)
            
            return {
                "verified": verification_status in ["verified", "trusted"],
                "did": did_document["id"],
                "trust_score": trust_score,
                "verification_status": verification_status,
                "details": {
                    "fingerprint_match": fingerprint_result["match"],
                    "behavioral_consistency": behavioral_result["consistent"],
                    "credential_valid": credential_result["valid"],
                    "trust_level": did_document.get("trust_level", "authenticated")
                },
                "processing_time_ms": verification_record["processing_time_ms"]
            }
            
        except Exception as e:
            logger.error(f"Identity verification error: {e}")
            return self._verification_failed(device_id, f"verification_error: {str(e)}")
    
    def _verify_device_fingerprint(self, device_id, device_info):
        """Verify device fingerprint against stored fingerprint"""
        if device_id not in self.device_fingerprints:
            return {"match": False, "reason": "no_stored_fingerprint"}
        
        stored_fingerprint = self.device_fingerprints[device_id]
        current_fingerprint = self._generate_device_fingerprint(device_info)
        
        # Compare key components
        stored_components = stored_fingerprint["components"]
        current_components = current_fingerprint["components"]
        
        matches = 0
        total_checks = 0
        
        for key in ["device_type", "firmware_version"]:
            total_checks += 1
            if stored_components.get(key) == current_components.get(key):
                matches += 1
        
        match_ratio = matches / total_checks if total_checks > 0 else 0
        
        return {
            "match": match_ratio >= 0.8,  # 80% match threshold
            "match_ratio": match_ratio,
            "differences": [
                key for key in ["device_type", "firmware_version"]
                if stored_components.get(key) != current_components.get(key)
            ]
        }
    
    def _verify_behavioral_consistency(self, device_id, device_info):
        """Verify behavioral consistency with previous interactions"""
        if device_id not in self.behavioral_profiles:
            # First interaction - establish baseline
            return {"consistent": True, "reason": "baseline_establishment"}
        
        profile = self.behavioral_profiles[device_id]
        
        # Check for behavioral anomalies
        inconsistencies = []
        
        # User profile consistency
        user_profile = device_info.get("user_profile", {})
        stored_profile = profile.get("user_profile", {})
        
        for key in ["experience_level", "play_style"]:
            if key in stored_profile and key in user_profile:
                if stored_profile[key] != user_profile[key]:
                    inconsistencies.append(f"user_profile_{key}_changed")
        
        # Temporal pattern consistency
        current_time = time.time()
        last_interaction = profile.get("last_interaction", current_time)
        time_diff = current_time - last_interaction
        
        if time_diff < 10:  # Very frequent interactions might be suspicious
            inconsistencies.append("unusually_frequent_interaction")
        
        return {
            "consistent": len(inconsistencies) == 0,
            "inconsistencies": inconsistencies,
            "profile_age": current_time - profile.get("created", current_time)
        }
    
    def _verify_device_credentials(self, device_id):
        """Verify device credentials and certificates"""
        # Check for valid credentials in store
        credentials = self.credential_store.get(device_id, [])
        
        valid_credentials = []
        expired_credentials = []
        
        current_time = datetime.now(timezone.utc)
        
        for credential in credentials:
            expiry_time = datetime.fromisoformat(credential.get("expirationDate", "2000-01-01T00:00:00Z").replace('Z', '+00:00'))
            
            if current_time < expiry_time:
                valid_credentials.append(credential)
            else:
                expired_credentials.append(credential)
        
        return {
            "valid": len(valid_credentials) > 0,
            "valid_count": len(valid_credentials),
            "expired_count": len(expired_credentials),
            "total_count": len(credentials)
        }
    
    def _calculate_trust_score(self, verification_results):
        """Calculate overall trust score from verification results"""
        fingerprint_result, behavioral_result, credential_result = verification_results
        
        score = 0.0
        
        # Fingerprint verification (40% weight)
        if fingerprint_result["match"]:
            score += 0.4
        else:
            score += 0.4 * fingerprint_result.get("match_ratio", 0)
        
        # Behavioral consistency (30% weight)
        if behavioral_result["consistent"]:
            score += 0.3
        else:
            # Partial score based on number of inconsistencies
            inconsistencies = len(behavioral_result.get("inconsistencies", []))
            if inconsistencies <= 1:
                score += 0.15
        
        # Credential validity (30% weight)
        if credential_result["valid"]:
            score += 0.3
        else:
            # Partial score if device is new (no credentials expected)
            if credential_result["total_count"] == 0:
                score += 0.15  # Neutral for new devices
        
        return min(1.0, score)
    
    def _determine_verification_status(self, trust_score):
        """Determine verification status based on trust score"""
        if trust_score >= 0.9:
            return "verified"
        elif trust_score >= 0.7:
            return "trusted"
        elif trust_score >= 0.5:
            return "authenticated"
        elif trust_score >= 0.3:
            return "unverified"
        else:
            return "suspicious"
    
    def _update_behavioral_profile(self, device_id, device_info, trust_score):
        """Update behavioral profile for device"""
        current_time = time.time()
        
        if device_id not in self.behavioral_profiles:
            self.behavioral_profiles[device_id] = {
                "created": current_time,
                "interaction_count": 0
            }
        
        profile = self.behavioral_profiles[device_id]
        
        # Update profile data
        profile["last_interaction"] = current_time
        profile["interaction_count"] += 1
        profile["last_trust_score"] = trust_score
        profile["user_profile"] = device_info.get("user_profile", {})
        
        # Track trust score history
        if "trust_history" not in profile:
            profile["trust_history"] = []
        
        profile["trust_history"].append({
            "timestamp": current_time,
            "trust_score": trust_score
        })
        
        # Keep only recent history
        if len(profile["trust_history"]) > 100:
            profile["trust_history"] = profile["trust_history"][-50:]
    
    def _verification_failed(self, device_id, reason):
        """Handle verification failure"""
        self.stats["failed_verifications"] += 1
        
        return {
            "verified": False,
            "reason": reason,
            "trust_score": 0.0,
            "verification_status": "failed"
        }
    
    def _log_verification_event(self, verification_record):
        """Log verification events"""
        try:
            with open('/app/results/logs/did_verifications.json', 'a') as f:
                f.write(json.dumps(verification_record) + '\n')
        except Exception as e:
            logger.debug(f"Could not write verification log: {e}")
    
    def issue_verifiable_credential(self, device_id, credential_type, attributes):
        """Issue a verifiable credential to a device"""
        try:
            # Create credential
            credential = {
                "id": f"urn:ce-cms:credential:{uuid.uuid4()}",
                "type": ["VerifiableCredential", credential_type],
                "issuer": "did:ce-cms:issuer",
                "issuanceDate": datetime.now(timezone.utc).isoformat(),
                "expirationDate": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                "credentialSubject": {
                    "id": self.did_registry.get(device_id, {}).get("id", f"did:ce-cms:{device_id}"),
                    **attributes
                },
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "verificationMethod": "did:ce-cms:issuer#key-1",
                    "proofPurpose": "assertionMethod",
                    "jws": self._create_credential_proof(attributes)
                }
            }
            
            # Store credential
            if device_id not in self.credential_store:
                self.credential_store[device_id] = []
            
            self.credential_store[device_id].append(credential)
            
            # Add to blockchain
            self._add_to_blockchain({
                "type": "credential_issued",
                "credential_id": credential["id"],
                "device_id": device_id,
                "timestamp": time.time()
            })
            
            self.stats["credentials_issued"] += 1
            
            logger.info(f"Issued credential {credential['id']} to device {device_id}")
            return credential
            
        except Exception as e:
            logger.error(f"Credential issuance error: {e}")
            return None
    
    def _create_credential_proof(self, attributes):
        """Create cryptographic proof for credential"""
        # Simplified JWT-based proof
        payload = {
            "iss": "did:ce-cms:issuer",
            "sub": "credential_proof",
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,  # 24 hours
            "attributes_hash": hashlib.sha256(
                json.dumps(attributes, sort_keys=True).encode()
            ).hexdigest()
        }
        
        return jwt.encode(payload, self.signing_key, algorithm="HS256")
    
    def revoke_credential(self, device_id, credential_id):
        """Revoke a verifiable credential"""
        try:
            credentials = self.credential_store.get(device_id, [])
            
            # Find and mark credential as revoked
            for credential in credentials:
                if credential["id"] == credential_id:
                    credential["status"] = "revoked"
                    credential["revocationDate"] = datetime.now(timezone.utc).isoformat()
                    
                    # Add to blockchain
                    self._add_to_blockchain({
                        "type": "credential_revoked",
                        "credential_id": credential_id,
                        "device_id": device_id,
                        "timestamp": time.time()
                    })
                    
                    self.stats["revoked_credentials"] += 1
                    
                    logger.info(f"Revoked credential {credential_id} for device {device_id}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Credential revocation error: {e}")
            return False
    
    def _add_to_blockchain(self, transaction):
        """Add transaction to blockchain ledger (simplified)"""
        block = {
            "id": len(self.blockchain_ledger),
            "timestamp": time.time(),
            "transaction": transaction,
            "previous_hash": self._get_previous_block_hash(),
            "hash": self._calculate_block_hash(transaction)
        }
        
        self.blockchain_ledger.append(block)
    
    def _get_previous_block_hash(self):
        """Get hash of previous block"""
        if not self.blockchain_ledger:
            return "genesis"
        
        return self.blockchain_ledger[-1]["hash"]
    
    def _calculate_block_hash(self, transaction):
        """Calculate hash for blockchain block"""
        block_data = {
            "transaction": transaction,
            "timestamp": time.time(),
            "previous_hash": self._get_previous_block_hash()
        }
        
        return hashlib.sha256(
            json.dumps(block_data, sort_keys=True).encode()
        ).hexdigest()
    
    def verify_credential_chain(self, device_id):
        """Verify credential chain integrity using blockchain"""
        device_transactions = [
            block for block in self.blockchain_ledger
            if block["transaction"].get("device_id") == device_id
        ]
        
        integrity_checks = []
        
        for i, block in enumerate(device_transactions):
            # Verify block hash
            expected_hash = self._calculate_block_hash(block["transaction"])
            hash_valid = block["hash"] == expected_hash
            
            # Verify chain continuity
            if i > 0:
                previous_block = device_transactions[i-1]
                chain_valid = block["previous_hash"] == previous_block["hash"]
            else:
                chain_valid = True
            
            integrity_checks.append({
                "block_id": block["id"],
                "hash_valid": hash_valid,
                "chain_valid": chain_valid,
                "transaction_type": block["transaction"]["type"]
            })
        
        overall_integrity = all(
            check["hash_valid"] and check["chain_valid"] 
            for check in integrity_checks
        )
        
        return {
            "integrity_valid": overall_integrity,
            "total_blocks": len(device_transactions),
            "integrity_checks": integrity_checks
        }
    
    def get_device_credentials(self, device_id):
        """Get all credentials for a device"""
        credentials = self.credential_store.get(device_id, [])
        
        # Filter out revoked credentials unless specifically requested
        active_credentials = [
            cred for cred in credentials 
            if cred.get("status") != "revoked"
        ]
        
        return {
            "device_id": device_id,
            "active_credentials": len(active_credentials),
            "total_credentials": len(credentials),
            "credentials": active_credentials
        }
    
    def cross_platform_identity_verification(self, device_id, platform_info):
        """Verify identity across different metaverse platforms"""
        try:
            # Get device DID
            did_document = self.did_registry.get(device_id)
            if not did_document:
                return {"verified": False, "reason": "no_did_found"}
            
            # Check for cross-platform credentials
            credentials = self.credential_store.get(device_id, [])
            cross_platform_creds = [
                cred for cred in credentials
                if "CrossPlatformIdentity" in cred.get("type", [])
            ]
            
            # Verify platform-specific attributes
            platform_verification = self._verify_platform_attributes(
                platform_info, cross_platform_creds
            )
            
            # Create portable identity token
            if platform_verification["valid"]:
                identity_token = self._create_portable_identity_token(
                    device_id, did_document, platform_info
                )
                
                return {
                    "verified": True,
                    "cross_platform_identity": identity_token,
                    "platform_verification": platform_verification,
                    "portability_score": self._calculate_portability_score(cross_platform_creds)
                }
            else:
                return {
                    "verified": False,
                    "reason": "platform_verification_failed",
                    "platform_verification": platform_verification
                }
                
        except Exception as e:
            logger.error(f"Cross-platform verification error: {e}")
            return {"verified": False, "reason": f"error: {str(e)}"}
    
    def _verify_platform_attributes(self, platform_info, credentials):
        """Verify platform-specific identity attributes"""
        required_attributes = platform_info.get("required_attributes", [])
        
        verified_attributes = []
        missing_attributes = []
        
        for attr in required_attributes:
            found = False
            for cred in credentials:
                cred_subject = cred.get("credentialSubject", {})
                if attr in cred_subject:
                    verified_attributes.append(attr)
                    found = True
                    break
            
            if not found:
                missing_attributes.append(attr)
        
        return {
            "valid": len(missing_attributes) == 0,
            "verified_attributes": verified_attributes,
            "missing_attributes": missing_attributes,
            "verification_score": len(verified_attributes) / max(1, len(required_attributes))
        }
    
    def _create_portable_identity_token(self, device_id, did_document, platform_info):
        """Create portable identity token for cross-platform use"""
        token_payload = {
            "iss": "did:ce-cms:issuer",
            "sub": did_document["id"],
            "aud": platform_info.get("platform_id", "unknown"),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # 1 hour
            "device_id": hashlib.sha256(device_id.encode()).hexdigest()[:16],  # Privacy-preserving
            "trust_level": did_document.get("trust_level", "authenticated"),
            "verification_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return jwt.encode(token_payload, self.signing_key, algorithm="HS256")
    
    def _calculate_portability_score(self, credentials):
        """Calculate how portable the identity is across platforms"""
        if not credentials:
            return 0.0
        
        portability_factors = {
            "cross_platform_attributes": 0.4,
            "standard_compliance": 0.3,
            "credential_freshness": 0.3
        }
        
        score = 0.0
        current_time = datetime.now(timezone.utc)
        
        for cred in credentials:
            # Check for cross-platform attributes
            cred_subject = cred.get("credentialSubject", {})
            cross_platform_attrs = len([
                key for key in cred_subject.keys()
                if key in ["avatar_id", "asset_ownership", "reputation_score"]
            ])
            
            if cross_platform_attrs > 0:
                score += portability_factors["cross_platform_attributes"]
            
            # Check standard compliance
            cred_types = cred.get("type", [])
            if any("W3C" in ctype or "DID" in ctype for ctype in cred_types):
                score += portability_factors["standard_compliance"]
            
            # Check credential freshness
            issued_date = datetime.fromisoformat(
                cred.get("issuanceDate", "2000-01-01T00:00:00Z").replace('Z', '+00:00')
            )
            days_old = (current_time - issued_date).days
            
            if days_old < 30:  # Fresh credential
                score += portability_factors["credential_freshness"]
        
        return min(1.0, score / len(credentials))
    
    def get_status(self):
        """Get DID service status"""
        return {
            "did_registry_size": len(self.did_registry),
            "credential_store_size": len(self.credential_store),
            "verification_history_size": len(self.verification_history),
            "blockchain_ledger_size": len(self.blockchain_ledger),
            "behavioral_profiles": len(self.behavioral_profiles),
            "statistics": self.stats,
            "trust_levels": list(self.trust_levels.keys())
        }
    
    def get_identity_analytics(self):
        """Get comprehensive identity analytics"""
        current_time = time.time()
        recent_cutoff = current_time - 3600  # Last hour
        
        # Recent verification analytics
        recent_verifications = [
            v for v in self.verification_history
            if time.mktime(datetime.fromisoformat(v["timestamp"].replace('Z', '+00:00')).timetuple()) > recent_cutoff
        ]
        
        # Calculate verification success rate
        if recent_verifications:
            success_rate = len([
                v for v in recent_verifications 
                if v["verification_status"] in ["verified", "trusted"]
            ]) / len(recent_verifications)
        else:
            success_rate = 0.0
        
        # Trust score distribution
        trust_scores = [v["trust_score"] for v in recent_verifications]
        avg_trust_score = sum(trust_scores) / max(1, len(trust_scores))
        
        # Device type distribution
        device_types = {}
        for device_id, did_doc in self.did_registry.items():
            device_type = did_doc.get("device_fingerprint", {}).get("components", {}).get("device_type", "unknown")
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        return {
            "recent_verifications": len(recent_verifications),
            "verification_success_rate": success_rate,
            "average_trust_score": avg_trust_score,
            "device_type_distribution": device_types,
            "credential_statistics": {
                "total_issued": self.stats["credentials_issued"],
                "total_revoked": self.stats["revoked_credentials"],
                "active_credentials": self.stats["credentials_issued"] - self.stats["revoked_credentials"]
            },
            "blockchain_integrity": len(self.blockchain_ledger) > 0
        }

# Example usage and testing
if __name__ == "__main__":
    did_service = DIDVerificationService()
    
    # Test device registration
    test_device_info = {
        "device_type": "vr_headset",
        "firmware_version": "1.2.3",
        "hardware_id": "VR001",
        "capabilities": ["head_tracking", "eye_tracking"]
    }
    
    device_id = "test_vr_device_001"
    
    # Create DID
    did_doc = did_service.create_did_document(device_id, test_device_info)
    print(f"Created DID: {did_doc['id'] if did_doc else 'Failed'}")
    
    # Issue credential
    credential = did_service.issue_verifiable_credential(
        device_id, 
        "VRDeviceCredential",
        {"device_certified": True, "security_level": "high"}
    )
    print(f"Issued credential: {credential['id'] if credential else 'Failed'}")
    
    # Verify identity
    verification_result = did_service.verify_device_identity(device_id, test_device_info)
    print(f"Verification result: {verification_result}")
    
    # Get status
    status = did_service.get_status()
    print(f"Service status: {status}")
    
    # Get analytics
    analytics = did_service.get_identity_analytics()
    print(f"Identity analytics: {analytics}")