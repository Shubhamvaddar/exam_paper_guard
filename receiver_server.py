import os
import sys
import socket
import json
import hashlib
from exam_guard import KeyManager, ExamGuardPackage, SecurityException, DecryptionException

HOST = "0.0.0.0"  # Listen on all network interfaces
PORT = 65432      # Port to listen on

KEYS_DIR = "coordinator_keys"
os.makedirs(KEYS_DIR, exist_ok=True)
PRIV_KEY_FILE = os.path.join(KEYS_DIR, "coord_private.pem")
PUB_KEY_FILE = os.path.join(KEYS_DIR, "coord_public.pem")
FACULTY_TRUSTED_PUB = os.path.join(KEYS_DIR, "faculty_public_trusted.pem")


def init_keys():
    """Generates RSA-4096 keypair for the Coordinator if not present."""
    if not os.path.exists(PRIV_KEY_FILE):
        print("[Coordinator] Generating RSA-4096 Key Pair...")
        priv_k, pub_k = KeyManager.generate_rsa_keypair(4096)
        KeyManager.save_private_key(priv_k, PRIV_KEY_FILE)
        KeyManager.save_public_key(pub_k, PUB_KEY_FILE)
        print(f"[Coordinator] Keys generated in '{KEYS_DIR}/'.")
        print(f"[ACTION REQUIRED] Send '{PUB_KEY_FILE}' to Laptop 1 (Faculty) via trusted channel.")
    else:
        print("[Coordinator] Keys already exist.")


def start_server():
    if not os.path.exists(FACULTY_TRUSTED_PUB):
        print(f"\n[ERROR] Missing Faculty public key at: '{FACULTY_TRUSTED_PUB}'")
        print("Obtain 'faculty_public.pem' from Laptop 1 and place it here as 'faculty_public_trusted.pem'.")
        return

    coord_priv = KeyManager.load_private_key(PRIV_KEY_FILE)
    faculty_pub = KeyManager.load_public_key(FACULTY_TRUSTED_PUB)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    print("\n" + "=" * 65)
    print(f"[COORDINATOR SERVER RUNNING] Listening on port {PORT}...")
    print("Waiting for confidential examination paper from Faculty...")
    print("=" * 65)

    while True:
        client_sock, client_addr = server.accept()
        print(f"\n[+] Incoming connection from {client_addr[0]}:{client_addr[1]}")

        # Receive 4-byte payload length header, then the JSON package
        try:
            raw_length = client_sock.recv(4)
            if not raw_length:
                client_sock.close()
                continue
            payload_len = int.from_bytes(raw_length, "big")
            
            data_chunks = []
            bytes_received = 0
            while bytes_received < payload_len:
                chunk = client_sock.recv(min(4096, payload_len - bytes_received))
                if not chunk:
                    break
                data_chunks.append(chunk)
                bytes_received += len(chunk)

            raw_json = b"".join(data_chunks).decode("utf-8")
            temp_pkg_path = "incoming_package.tmp"
            with open(temp_pkg_path, "w", encoding="utf-8") as f:
                f.write(raw_json)

            print("[+] Complete package received over the network. Verifying...")

            # Cryptographic Verification & Decryption
            output_paper_path = "RECOVERED_EXAMINATION_PAPER.txt"
            metadata = ExamGuardPackage.verify_and_decrypt(
                package_path=temp_pkg_path,
                sender_public_key=faculty_pub,
                recipient_private_key=coord_priv,
                output_file_path=output_paper_path
            )

            with open(output_paper_path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()

            print("\n" + "*" * 65)
            print("[SUCCESS] EXAMINATION PAPER SAFELY RECEIVED AND AUTHENTICATED")
            print("*" * 65)
            print(f"  - Verified Sender ID : {metadata['sender_id']}")
            print(f"  - Destination ID     : {metadata['recipient_id']}")
            print(f"  - Timestamp (UTC)    : {metadata['timestamp_utc']}")
            print(f"  - Paper SHA-256 Hash : {sha}")
            print(f"  - Saved Plaintext to : {os.path.abspath(output_paper_path)}")
            print("*" * 65)

            # Send positive ACK back to sender
            client_sock.sendall(b"OK: VERIFIED AND DECRYPTED")

        except SecurityException as se:
            print("\n" + "!" * 65)
            print(f"[SECURITY ALERT] {se}")
            print("Action: Package rejected. No plaintext written to disk.")
            print("!" * 65)
            client_sock.sendall(f"FAIL: {se}".encode("utf-8"))

        except DecryptionException as de:
            print(f"\n[ERROR] Decryption failure: {de}")
            client_sock.sendall(f"FAIL: {de}".encode("utf-8"))

        except Exception as e:
            print(f"\n[ERROR] Network error: {e}")
        finally:
            client_sock.close()
            if os.path.exists("incoming_package.tmp"):
                os.remove("incoming_package.tmp")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python receiver_server.py init-keys")
        print("  python receiver_server.py listen")
        sys.exit(1)

    if sys.argv[1] == "init-keys":
        init_keys()
    elif sys.argv[1] == "listen":
        start_server()
