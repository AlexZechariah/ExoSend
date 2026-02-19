# ExoSend

> Decentralized local file transfer system for Windows 10

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%2010-blue.svg)](https://www.microsoft.com/windows)

ExoSend enables seamless peer-to-peer file transfers over local WiFi networks without requiring internet connectivity or cloud services. Features automatic peer discovery, TLS 1.2+ encryption, SHA-256 verification, and high-performance transfer.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Firewall Configuration](#firewall-configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Zero-Configuration Discovery** - Automatic peer detection via UDP broadcast
- **Direct P2P Transfers** - No cloud services or internet required
- **TLS 1.2+ Encryption** - Secure file transfers with self-signed certificates
- **SHA-256 Verification** - Integrity checking for all transferred files
- **Qt6 GUI** - Modern Windows 10 desktop application with system tray

---

## Quick Start

### Prerequisites

- Windows 10 x64

### Installation

1. Download the latest release from [Releases](https://github.com/yourusername/ExoSend/releases)
2. Extract the ZIP file
3. Run `ExoSend.exe`

### Quick Transfer

1. Launch ExoSend on both computers
2. Peers will auto-discover each other within 3 seconds
3. Drag and drop files to send

---

## Usage

### GUI Application

**Features:**
- Peer list with auto-discovery
- Drag-and-drop file sending
- Progress tracking with speed/ETA
- System tray minimize
- Settings persistence

### Firewall Configuration

ExoSend requires Windows Firewall rules for:
- **UDP port 8888** - Peer discovery beacons
- **TCP port 9999** - File transfer connections

The application will prompt to configure these rules automatically on first run.

### Manual Firewall Setup

If automatic setup fails, open Windows Firewall with Advanced Security:
1. Inbound Rules → New Rule
2. Port → UDP → 8888 → Allow → Name: "ExoSend Discovery"
3. Port → TCP → 9999 → Allow → Name: "ExoSend Transfer"

---

## Troubleshooting

### Peers Not Discovering Each Other

**Solutions:**
1. Check firewall rules (see [Firewall Configuration](#firewall-configuration))
2. Verify both devices are on the same network
3. Check for VPN interference (disable VPN temporarily)
4. Verify UDP port 8888 is not blocked

### Transfer Fails Immediately

**Solutions:**
1. Check firewall TCP port 9999
2. Verify sufficient disk space
3. Check file permissions on download directory
4. Disable antivirus temporarily (add ExoSend to exclusions)

### Certificate Errors

**Solutions:**
1. Delete `%APPDATA%\ExoSend\certs\` folder
2. Restart ExoSend (certificate auto-generates)
3. Verify system time is correct

---

## Certificate Management

ExoSend uses TLS 1.2+ encryption with self-signed certificates automatically generated on first run.

Certificates are stored in: `%APPDATA%\ExoSend\certs\`

**Security Notes:**
- Self-signed certificates provide encryption but NOT authentication
- For production use, consider implementing certificate authority (CA) support

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

**ExoSend** - Fast, secure, local file transfers for Windows 10.
