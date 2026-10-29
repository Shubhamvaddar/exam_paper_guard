# Exam Paper Guard

A secure file-transfer project designed to transfer examination papers between two separate systems: a Sender and a Receiver. The project uses a common security component, key management, trusted public-key exchange, and a network connection to transfer files.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Running the Project](#running-the-project)
- [Finding the Receiver IP Address](#finding-the-receiver-ip-address)
- [Exchanging Public Keys](#exchanging-public-keys)
- [Sending a File](#sending-a-file)
- [Tamper Testing](#tamper-testing)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

## Overview

Exam Paper Guard is intended to help protect examination papers during file transfer between two systems.

The project uses two role-specific programs:

- `sender_client.py` — runs on the Sender system and initiates file transfers.
- `receiver_server.py` — runs on the Receiver system and handles incoming transfers.

Both systems also use the common `exam_guard.py` component.

## Architecture

### Sender System

The Sender system is responsible for:

- Running the common security component.
- Initializing the sender's keys.
- Storing the receiver's trusted public key.
- Connecting to the configured coordinator.
- Selecting and sending a file.

### Receiver System

The Receiver system is responsible for:

- Running the common security component.
- Running the receiver-side server.
- Generating its keys using the supported initialization procedure.
- Storing the sender's trusted public key.
- Accepting incoming file transfers.

### Communication Workflow

1. Prepare the project on both systems.
2. Run `exam_guard.py` on both systems as required.
3. Initialize the sender and receiver keys using the supported commands.
4. Exchange public keys through a separate trusted channel.
5. Save the received public keys in the respective `keys/` directories using the required `_trusted` naming convention.
6. Start the receiver server and ensure the coordinator is available.
7. Send the file from the Sender system.
8. Verify that the transfer completes and that the receiver obtains the expected file.

## Requirements

- Python installed on both systems.
- The project repository or project files available on both systems.
- All dependencies required by the project installed.
- Network connectivity between the participating systems.
- Firewall rules permitting the required application traffic.
- Public keys exchanged and verified through a trusted channel.

## Project Structure

The following is the logical structure. Actual filenames and folders may vary depending on the implementation.

```text
exam_paper_guard/
├── exam_guard.py
├── sender_client.py
├── receiver_server.py
├── keys/
│   ├── generated-key-files
│   └── trusted-public-key-files
├── README.md
└── .gitignore
```

The `keys/` directory stores the key files created or used by the project.

## Setup

### 1. Obtain the Project on Both Systems

Clone the repository on both the Sender and Receiver systems:

```bash
git clone https://github.com/Shubhamvaddar/exam_paper_guard.git
cd exam_paper_guard
```

If Git is not installed, download the repository as a ZIP file from GitHub and extract it.

### 2. Check Python

On Windows:

```powershell
python --version
```

On Linux or macOS:

```bash
python3 --version
```

Use the Python command appropriate for your operating system. The remaining examples use `python` for consistency with the tested Windows commands.

### 3. Install Dependencies

Install the dependencies specified by the project. If a `requirements.txt` file exists, run:

```bash
python -m pip install -r requirements.txt
```

If the project does not contain this file, follow its actual dependency instructions instead.

## Running the Project

### Step 1: Run the Common Component

On both the Sender and Receiver systems, open a terminal in the project directory and run:

```bash
python exam_guard.py
```

Follow any instructions printed by the program.

### Step 2: Initialize Sender Keys

On the Sender system, run:

```bash
python sender_client.py init-keys
```

This is the key-initialization command shown by the sender client's usage instructions.

Check the `keys/` directory for the generated key files.

### Step 3: Initialize Receiver Keys

On the Receiver system, use the receiver's supported key-initialization command.

The exact command must be confirmed from `receiver_server.py` or its usage instructions; do not assume that it is identical to the sender's command.

### Step 4: Exchange Public Keys

Exchange the public keys through a separate trusted channel, such as a verified in-person transfer or another secure method.

Never exchange private keys.

Save each received public key in the appropriate `keys/` directory using the required `_trusted` filename convention. Verify the key's authenticity before trusting it.

### Step 5: Start the Receiver

Start the receiver server using the actual command supported by `receiver_server.py`.

Keep the server running while the sender connects.

If the application requires a separate coordinator, ensure that the coordinator is running and that you know its IP address.

## Finding the Receiver IP Address

The Sender needs the correct network address expected by the application. When the receiver itself is the connection endpoint, use the receiver's reachable IP address.

### Windows

Open PowerShell or Command Prompt on the Receiver system:

```powershell
ipconfig
```

Find the active Wi-Fi or Ethernet adapter and locate its `IPv4 Address`.

Example:

```text
IPv4 Address . . . . . . . . . . : 192.168.1.35
```

Use the actual address shown on your system.

### Linux — Ubuntu, Fedora, Debian

Open a terminal on the Receiver system:

```bash
ip addr
```

Alternatively:

```bash
hostname -I
```

Find the IPv4 address belonging to the active network interface. Do not use `127.0.0.1` for communication between separate computers.

### macOS

Open Terminal on the Receiver system:

```bash
ipconfig getifaddr en0
```

If that does not return an address, identify the network interface:

```bash
networksetup -listallhardwareports
```

Then run `ipconfig getifaddr` with the correct interface name.

### Network Notes

- Both systems should be able to reach each other.
- On the same local network, use the receiver's active local IPv4 address when the application expects it.
- If the application expects a coordinator address, use the coordinator's IP instead.
- If the systems are on different networks, a VPN or another appropriate network configuration may be necessary.
- Ensure that the application's required port is allowed through the firewall.

## Exchanging Public Keys

Public-key exchange is a required preparation step before transferring sensitive files.

1. Generate the necessary keys on both systems.
2. Identify the public-key files.
3. Exchange only the public keys using a trusted channel.
4. Verify their authenticity or fingerprints using the project's supported procedure.
5. Save each received public key in the appropriate `keys/` directory.
6. Use the expected `_trusted` filename convention.
7. Confirm that the application loads the trusted key files correctly.

Example filename convention:

```text
sender_public_trusted.pem
receiver_public_trusted.pem
```

These are illustrative names only. Use the exact filenames and formats expected by the implementation.

## Sending a File

The sender client's documented usage is:

```text
python sender_client.py init-keys

python sender_client.py send <COORDINATOR_IP> <FILE_PATH> [--tamper]
```

### Basic Transfer

On the Sender system, run:

```powershell
python sender_client.py send <COORDINATOR_IP> <FILE_PATH>
```

Replace:

- `<COORDINATOR_IP>` with the actual coordinator IP address.
- `<FILE_PATH>` with the path of the file to transfer.

Example:

```powershell
python sender_client.py send 192.168.1.35 final_exam.txt
```

The IP address and filename are examples. Use the actual values for your setup.

If the file is stored at another location, provide its correct path. For paths containing spaces, use quotation marks:

```powershell
python sender_client.py send 192.168.1.35 "C:\Users\Student\Documents\final exam.txt"
```

Wait for the sender's result and verify that the receiver has received the expected file.

## Tamper Testing

The sender client supports an optional `--tamper` flag in its documented usage.

Example:

```powershell
python sender_client.py send 192.168.1.35 final_exam.txt --tamper
```

Use this option only in an authorized test environment.

Check the application's output and receiver-side behavior to determine whether tampering was detected or the transfer was rejected. The exact expected result depends on the implemented security mechanism.

## Troubleshooting

### Python Is Not Recognized

Check whether Python is installed:

```powershell
python --version
```

If the command is unavailable, install Python or correct the PATH configuration.

### Connection Fails

- Verify the coordinator or receiver IP address.
- Ensure the receiver server is running.
- Check network connectivity.
- Confirm that the required port is open.
- Verify that both systems use compatible project configurations.

### Trusted Key Is Missing

- Check the `keys/` directory on both systems.
- Confirm that the public keys were exchanged successfully.
- Check the expected filenames and `_trusted` naming convention.
- Verify that the application is loading the correct key files.

### File Not Found

- Confirm the file path.
- Use quotation marks around paths containing spaces.
- Verify that the file exists on the Sender system.

### Transfer Is Rejected

Check the program's output, trusted-key configuration, connection settings, and any integrity or authentication errors.

## Security Notes

- Never share private keys.
- Verify public keys before trusting them.
- Keep private keys and examination papers out of version control.
- Do not commit passwords, tokens, or other secrets.
- Use `.gitignore` to exclude sensitive and generated files that should not be tracked.
- Remember that `.gitignore` does not remove files already committed to Git.
- Use the tamper-testing option only in an authorized environment.
- Test the complete workflow with non-sensitive sample files before transferring real examination papers.

## Contributing

Suggestions, bug reports, and improvements are welcome. Please open an issue or submit a pull request describing the proposed change.

## License

Add a license file if you intend to publish the project under an open-source license.
