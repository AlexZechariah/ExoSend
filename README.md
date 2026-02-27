# ExoSend

> Local peer-to-peer file transfers for Windows 10

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%2010-blue.svg)](https://www.microsoft.com/windows)

ExoSend provides peer-to-peer file transfers over local WiFi networks without requiring internet connectivity or cloud services. It includes automatic peer discovery, TLS 1.3 encryption, SHA-256 verification, secure pairing, and transfer progress tracking.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Pairing and Trust](#pairing-and-trust)
- [Firewall Configuration](#firewall-configuration)
- [Troubleshooting](#troubleshooting)
- [Certificate Management](#certificate-management)
- [License](#license)

---

## Features

- **Automatic Discovery** - Peer detection via UDP broadcast
- **Direct P2P Transfers** - No cloud services or internet required
- **TLS 1.3 Encryption** - Secure file transfers with self-signed certificates
- **SHA-256 Verification** - Integrity checking for all transferred files
- **Qt6 GUI** - Modern Windows 10 desktop application with system tray

---

## Quick Start

### Prerequisites

- Windows 10 x64

### Installation

1. Download the latest release from [Releases](https://github.com/AlexZechariah/ExoSend/releases)
2. Extract the ZIP file
3. Run `ExoSend.exe`

### Quick Transfer

1. Launch ExoSend on both computers
2. Peers will auto-discover each other within 3 seconds
3. Select a peer, then drag and drop files to send

---

## Usage

### GUI Application

**Features:**
- Peer list with auto-discovery
- Drag-and-drop file sending
- Progress tracking with speed/ETA
- System tray minimize
- Settings persistence

## Pairing and Trust

ExoSend requires secure pairing before transfers. Pairing pins the peer's TLS certificate fingerprint in a DPAPI-protected trust store, but only after the pairing phrase is verified.

### First-time pairing (secure, fail-closed)

When you transfer to a new peer:

1. ExoSend establishes a mutual TLS 1.3 connection using self-signed certificates.
2. ExoSend performs pairing confirmation using:
   - A **high-entropy pairing phrase** entered out-of-band (12 RFC 1751 words representing 128 bits of entropy).
     - Share format: one hyphen-separated line (`word1-word2-...-word12`) to avoid whitespace/newline issues in messaging apps.
   - A TLS channel binding derived from the handshake (RFC 9266 `tls-exporter`, `EXPORTER-Channel-Binding`).
3. Only if the confirmation succeeds does ExoSend pin the peer certificate fingerprint.

This design prevents pre-pairing MITM unless the attacker also learns the pairing phrase.

### Subsequent connections

- If the pinned fingerprint matches, transfers proceed.
- If a pinned peer's fingerprint changes, ExoSend blocks the transfer and requires re-pairing with a new pairing phrase.

Pairing and settings are stored per-machine in the user profile (typically under `%LOCALAPPDATA%`), and are not transferred when you copy the app folder to another PC or VM.

### Factory Reset

In the GUI, **Settings → Factory Reset…** resets ExoSend back to a “first use” trust state by:
- Resetting preferences to defaults
- Forgetting all paired peers (clears the trust store)
- Clearing per-peer auto-accept preferences

Factory Reset does **not** rotate TLS certificates and does **not** change the device UUID. To remove all user data (including TLS identity and UUID) use the uninstaller’s “Remove user data” option.

### Firewall Configuration

ExoSend uses dynamic ports:

- **UDP discovery** binds to one port from a small pool (see `include/exosend/config.h`) and broadcasts beacons to the entire pool.
- **TCP transfers** listen on an OS-assigned ephemeral port (`bind(0)`), and that port is advertised in discovery beacons.

Because the TCP listen port is dynamic, **port-based firewall rules are not reliable**. ExoSend uses **program-based** Windows Firewall rules scoped to:

- Profiles: **Private** and **Domain** (Public excluded by design)
- Remote address: **LocalSubnet** only

On startup, ExoSend checks whether the required rules exist and can install them automatically (requires Administrator approval via UAC). Ensure `ExoSendFirewallHelper.exe` is present next to `ExoSend.exe`.

### Manual Firewall Setup

If automatic setup fails, prefer a program-based inbound rule for `ExoSend.exe` (not a port rule).

Example (PowerShell as Administrator, adjust the path):

```powershell
New-NetFirewallRule `
  -DisplayName 'ExoSend (Private+Domain, LocalSubnet)' `
  -Direction Inbound `
  -Action Allow `
  -Program 'C:\Path\To\ExoSend.exe' `
  -Profile Private,Domain `
  -RemoteAddress LocalSubnet
```

---

## Troubleshooting

### Peers Not Discovering Each Other

**Solutions:**
1. Check firewall rules (see [Firewall Configuration](#firewall-configuration))
2. Verify both devices are on the same network
3. Check for VPN interference (disable VPN temporarily)
4. Ensure the network profile is **Private** (Public networks are intentionally not allowed by the default firewall rules)

### Transfer Fails Immediately

**Solutions:**
1. Check firewall rules (program-based inbound rule for `ExoSend.exe` on Private/Domain + LocalSubnet)
2. Verify sufficient disk space
3. Check file permissions on download directory
4. Disable antivirus temporarily (add ExoSend to exclusions)

### Certificate Errors

**Solutions:**
1. Delete `%LOCALAPPDATA%\ExoSend\certs\` folder
2. Restart ExoSend (certificate auto-generates)
3. Verify system time is correct

---

## Certificate Management

ExoSend uses TLS 1.3 encryption with self-signed certificates automatically generated on first run.

Certificates are stored in: `%LOCALAPPDATA%\ExoSend\certs\`

**Security Notes:**
- Self-signed certificates provide encryption. Peer authentication is enforced by secure pairing confirmation plus certificate fingerprint pinning.
- Discovery is untrusted and is used only to find peers, not to establish identity.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **nlohmann/json** - JSON parsing library
- **OpenSSL** - TLS/SSL and SHA-256 implementation
- **Qt6** - Cross-platform GUI framework
- **vcpkg** - C++ package manager

---

**ExoSend** - Local file transfers for Windows 10.
