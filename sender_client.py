"""
sender_client.py - Run on Laptop 1 (Faculty Member)
Encrypts the exam paper, signs the package, and sends it to Laptop 2's IP address.
Includes a '--tamper' flag to demonstrate live network attack detection!
"""
import os
import sys
import socket
import json
from exam_guard import KeyManager, ExamGuardPackage

KEYS_DIR = "faculty_keys"
os.makedirs(KEYS_DIR, exist_ok=True)
PRIV_KEY_FILE = os.path.join(KEYS_DIR, "faculty_private.pem")
PUB_KEY_FILE = os.path.join(KEYS_DIR, "faculty_public.pem")
COORD_TRUSTED_PUB = os.path.join(KEYS_DIR, "coord_public_trusted.pem")


def init_keys():
    """Generates RSA-4096 keypair for Faculty if not present."""
    if not os.path.exists(PRIV_KEY_FILE):
        print("[Faculty] Generating RSA-4096 Key Pair...")
        priv_k, pub_k = KeyManager.generate_rsa_keypair(4096)
        KeyManager.save_private_key(priv_k, PRIV_KEY_FILE)
        KeyManager.save_public_key(pub_k, PUB_KEY_FILE)
        print(f"[Faculty] Keys generated in '{KEYS_DIR}/'.")
        print(f"[ACTION REQUIRED] Send '{PUB_KEY_FILE}' to Laptop 2 (Coordinator) via trusted channel.")
    else:
        print("[Faculty] Keys already exist.")


def send_exam_paper(receiver_ip: str, file_path: str, port: int = 65432, tamper: bool = False):
    if not os.path.exists(COORD_TRUSTED_PUB):
        print(f"\n[ERROR] Missing Coordinator public key at: '{COORD_TRUSTED_PUB}'")
        print("Obtain 'coord_public.pem' from Laptop 2 and place it here as 'coord_public_trusted.pem'.")
        return

    if not os.path.exists(file_path):
        print(f"[ERROR] File '{file_path}' does not exist.")
        return

    faculty_priv = KeyManager.load_private_key(PRIV_KEY_FILE)
    coord_pub = KeyManager.load_public_key(COORD_TRUSTED_PUB)

    temp_package = "temp_out.encpkg"
    print(f"\n[+] Encrypting '{file_path}' with AES-256-GCM...")
    print("[+] Encrypting session key using Coordinator's RSA-4096 Public Key (OAEP)...")
    print("[+] Signing complete package using Faculty RSA-4096 Private Key (PSS)...")

    ExamGuardPackage.encrypt_and_package(
        source_file_path=file_path,
        recipient_public_key=coord_pub,
        sender_private_key=faculty_priv,
        sender_id="FACULTY_DR_ALICE",
        recipient_id="COORD_DR_BOB",
        output_package_path=temp_package
    )

    with open(temp_package, "r", encoding="utf-8") as f:
        pkg_data = json.load(f)

    # Simulation: Attacker modifies the ciphertext on the wire
    if tamper:
        print("\n[ATTACK SIMULATION] Flipping bits in the ciphertext to simulate Man-in-the-Middle tampering...")
        c = list(pkg_data["ciphertext"])
        c[15] = "Z" if c[15] != "Z" else "A"
        pkg_data["ciphertext"] = "".join(c)

    payload_bytes = json.dumps(pkg_data).encode("utf-8")

    print(f"[+] Connecting to Coordinator laptop at {receiver_ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((receiver_ip, port))

        # Send 4-byte payload length prefix, then the JSON payload
        s.sendall(len(payload_bytes).to_bytes(4, "big"))
        s.sendall(payload_bytes)

        # Receive acknowledgment
        response = s.recv(1024).decode("utf-8")
        print("\n" + "=" * 65)
        print(f"[SERVER RESPONSE] {response}")
        print("=" * 65)
        s.close()
    except Exception as e:
        print(f"\n[NETWORK ERROR] Could not connect to {receiver_ip}:{port} -> {e}")
    finally:
        if os.path.exists(temp_package):
            os.remove(temp_package)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python sender_client.py init-keys")
        print("  python sender_client.py send <COORDINATOR_IP> <FILE_PATH> [--tamper]")
        print("\nExample:")
        print("  python sender_client.py send 192.168.1.35 final_exam.txt")
        print("  python sender_client.py send 192.168.1.35 final_exam.txt --tamper")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "init-keys":
        init_keys()
    elif cmd == "send":
        if len(sys.argv) < 4:
            print("Error: Missing IP or file path.")
            sys.exit(1)
        ip = sys.argv[2]
        file_path = sys.argv[3]
        tamper = "--tamper" in sys.argv
        send_exam_paper(ip, file_path, tamper=tamper)