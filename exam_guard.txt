"""
exam_guard.py
Cryptographic engine for confidential examination paper transmission.
Implements:
  - RSA-4096 Key Generation & PEM Serialization
  - AES-256-GCM File Encryption
  - RSA-OAEP Session Key Wrapping (SHA-256)
  - RSA-PSS Package Signature (SHA-256)
  - Atomic Verification-before-Decryption
"""

import os
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class SecurityException(Exception):
    """Raised when package integrity or authenticity verification fails."""
    pass


class DecryptionException(Exception):
    """Raised when cryptographic decryption fails."""
    pass


class KeyManager:
    """Handles RSA-4096 key pair generation, persistence, and loading."""

    @staticmethod
    def generate_rsa_keypair(key_size: int = 4096) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates a high-security RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    @staticmethod
    def save_private_key(private_key: rsa.RSAPrivateKey, filepath: str, password: str | None = None) -> None:
        """Saves an RSA private key in PKCS#8 PEM format."""
        encryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        with open(filepath, "wb") as f:
            f.write(pem)

    @staticmethod
    def save_public_key(public_key: rsa.RSAPublicKey, filepath: str) -> None:
        """Saves an RSA public key in SubjectPublicKeyInfo PEM format."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_private_key(filepath: str, password: str | None = None) -> rsa.RSAPrivateKey:
        """Loads an RSA private key from a PEM file."""
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode("utf-8") if password else None
            )

    @staticmethod
    def load_public_key(filepath: str) -> rsa.RSAPublicKey:
        """Loads an RSA public key from a PEM file."""
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read())


class ExamGuardPackage:
    """Handles packaging, encryption, signing, verification, and decryption."""

    @staticmethod
    def _compute_canonical_bytes(metadata_json: str, enc_session_key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
        """
        Creates a deterministic byte sequence representing the package payload.
        Ensures signature covers all critical structural components.
        """
        return (
            len(metadata_json).to_bytes(4, "big") + metadata_json.encode("utf-8") +
            len(enc_session_key).to_bytes(4, "big") + enc_session_key +
            len(nonce).to_bytes(4, "big") + nonce +
            len(tag).to_bytes(4, "big") + tag +
            len(ciphertext).to_bytes(8, "big") + ciphertext
        )

    @classmethod
    def encrypt_and_package(
        cls,
        source_file_path: str,
        recipient_public_key: rsa.RSAPublicKey,
        sender_private_key: rsa.RSAPrivateKey,
        sender_id: str,
        recipient_id: str,
        output_package_path: str
    ) -> None:
        """
        Protects the input file using Hybrid Encryption (AES-256-GCM + RSA-4096-OAEP)
        and signs the package using RSA-4096-PSS.
        """
        with open(source_file_path, "rb") as f:
            plaintext = f.read()

        # 1. Generate fresh AES-256 key (32 bytes) and fresh random nonce (12 bytes for GCM)
        session_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)

        # 2. Encrypt plaintext using AES-256-GCM
        # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
        aesgcm = AESGCM(session_key)
        encrypted_data = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        ciphertext = encrypted_data[:-16]
        auth_tag = encrypted_data[-16:]

        # 3. Protect Session Key using Recipient RSA Public Key (RSA-OAEP with SHA-256)
        encrypted_session_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Construct canonical metadata
        metadata = {
            "version": "1.0",
            "source_filename": os.path.basename(source_file_path),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "file_size_bytes": len(plaintext)
        }
        metadata_json = json.dumps(metadata, sort_keys=True)

        # 5. Sign the complete encrypted package using Sender RSA Private Key (RSA-PSS with SHA-256)
        canonical_payload = cls._compute_canonical_bytes(
            metadata_json, encrypted_session_key, nonce, auth_tag, ciphertext
        )
        signature = sender_private_key.sign(
            canonical_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 6. Format into transport container
        transport_package = {
            "metadata": metadata,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(auth_tag).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii")
        }

        with open(output_package_path, "w", encoding="utf-8") as f:
            json.dump(transport_package, f, indent=2)

    @classmethod
    def verify_and_decrypt(
        cls,
        package_path: str,
        sender_public_key: rsa.RSAPublicKey,
        recipient_private_key: rsa.RSAPrivateKey,
        output_file_path: str
    ) -> dict:
        """
        Verifies sender signature and decrypts the package.
        Plaintext is written to disk ONLY after all verification checks pass.
        """
        with open(package_path, "r", encoding="utf-8") as f:
            try:
                pkg = json.load(f)
                metadata = pkg["metadata"]
                metadata_json = json.dumps(metadata, sort_keys=True)
                enc_session_key = base64.b64decode(pkg["encrypted_session_key"])
                nonce = base64.b64decode(pkg["nonce"])
                tag = base64.b64decode(pkg["tag"])
                ciphertext = base64.b64decode(pkg["ciphertext"])
                signature = base64.b64decode(pkg["signature"])
            except Exception as e:
                raise SecurityException(f"Package structure corrupted or invalid JSON: {e}")

        # Step 1: Verify digital signature using sender's public key
        canonical_payload = cls._compute_canonical_bytes(
            metadata_json, enc_session_key, nonce, tag, ciphertext
        )
        try:
            sender_public_key.verify(
                signature,
                canonical_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            raise SecurityException(
                "CRITICAL: Signature verification failed! Package has been tampered with or sender is unverified."
            )

        # Step 2: Recover AES session key using recipient's private key
        try:
            session_key = recipient_private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise DecryptionException(f"Failed to decrypt session key with the provided private key: {e}")

        # Step 3: Decrypt ciphertext and verify GCM authentication tag
        try:
            aesgcm = AESGCM(session_key)
            # Reconstruct the combined ciphertext + tag payload expected by AESGCM
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)
        except Exception as e:
            raise SecurityException(f"AES-GCM decryption/tag verification failed: {e}")

        # Step 4: Write plaintext output only after successful validation
        with open(output_file_path, "wb") as f:
            f.write(plaintext)

        return metadata