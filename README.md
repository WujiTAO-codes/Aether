# Aether

A secure, peer-to-peer file-sharing tool for local networks (LAN/WiFi) — no internet, no central server, no account required. Devices find each other automatically and transfer files directly, encrypted end to end.

Inspired by tools like LocalSend, built from scratch as a learning project covering networking fundamentals (UDP/TCP, sockets, threading) and applied security engineering (identity, trust, encryption).

---

## Features

- **Automatic discovery** — devices on the same network find each other without any manual setup (IP addresses, pairing codes, etc.)
- **Verified device identity** — every device has a unique, persistent identity that can't be trivially spoofed or duplicated by another device on the network
- **Encrypted transfers** — file contents and metadata are encrypted in transit; nothing is sent in plaintext
- **Trust memory** — the app remembers devices you've talked to before and will warn you if a device's identity ever changes unexpectedly
- **Safe by default** — incoming files always require your explicit approval before anything is written to disk; unsafe filenames and oversized/malformed requests are rejected automatically
- **Integrity checking** — every received file is verified against the sender's checksum, so corrupted or tampered transfers are caught and discarded rather than silently saved
- **No cloud, no accounts** — everything happens directly between devices on your local network

---

## How It Works (High Level)

Aether runs two things at once on every device:

1. **Discovery** — a lightweight background process that periodically announces "I'm here" to the local network and listens for the same from other devices. This is how the app builds the list of "nearby devices" you see in the menu.
2. **Transfer** — a background listener ready to receive an incoming file at any time, alongside the ability to initiate a send to any discovered device.

Both run as background threads, so a device can be discovering peers and receiving a file at the same time, without blocking the menu you interact with.

---

## Requirements

- Python 3.9+
- The `cryptography` Python package

Install dependencies:

```bash
pip install -r requirements.txt
```

(or, if you're not using a virtual environment: `pip install cryptography`)

---

## Running Aether

```bash
python3 main.py
```

You'll be asked to give your device a display name (e.g. `Aayush-Laptop`). After that, the app will:
- Start broadcasting its presence on the local network
- Start listening for other devices
- Start listening for incoming file transfers
- Show you a menu of nearby devices

### Menu options
[s] Send a file
[r] Refresh device list
[q] Quit

### Sending a file

1. Press `s`
2. Select a device from the numbered list
3. Enter the full path to the file you want to send
4. Watch the progress bar; you'll get a clear success or failure message when it's done

### Receiving a file

No action needed to *start* receiving — it happens automatically in the background. When someone sends you a file, you'll see a prompt:

Incoming file from <device>: <filename> (<size>)
Accept? (y/n):

Accepted files are saved into the `received/` folder inside the project directory.

### First time seeing a device

New devices are clearly labeled as `(new device — first time seen)` the first time they appear. This is expected and normal — you don't need to do anything differently.

### If a device's identity changes

If a device you've talked to before suddenly shows up with a different underlying identity, Aether will show a clear warning before letting you interact with it, and will ask for explicit confirmation before proceeding. This is a safety mechanism — if you don't recognize why the identity would have changed (e.g. the other person didn't mention reinstalling the app), it's safest to decline and investigate.

---

## Project Structure

aether/
├── main.py              # CLI entry point — the menu you interact with
├── identity.py          # Manages this device's persistent identity
├── discovery.py         # Finds other devices on the network
├── trust.py             # Remembers known devices and flags identity changes
├── transfer.py          # Handles sending and receiving files
├── utils.py             # Small shared helper functions
├── received/            # Where accepted incoming files are saved
├── requirements.txt     # Python dependencies
└── trusted_devices.json # Local record of previously-seen devices (not synced/shared)

---

## Local Testing (Two "Devices" on One Machine)

You can test Aether fully without needing two physical devices, by running two terminals on the same computer with different environment variable overrides so each behaves as an independent device:

**Terminal 1:**
```bash
AETHER_IDENTITY_DIR=/tmp/aether_device_a AETHER_TCP_PORT=54546 python3 main.py
```

**Terminal 2:**
```bash
AETHER_IDENTITY_DIR=/tmp/aether_device_b AETHER_TCP_PORT=54547 python3 main.py
```

Give each a different display name. After a few seconds, press `r` in both to refresh the device list — they should discover each other and be ready to send/receive files, just like two separate devices on the same network.

---

## Known Limitations

- Command-line interface only — no graphical UI
- Large file transfers currently load progress in memory chunk by chunk (no resumable transfers if interrupted)
- Display names are not required to be unique — two devices could choose the same name (this is a usability quirk, not a functional issue, since devices are still distinguished internally)
- Designed and tested for trusted local networks (home WiFi, etc.) — not intended for use on fully public/untrusted networks without further hardening

---

## Why "Aether"?

In classical physics, the aether was the theorized invisible medium that carried light and signals through space. Fitting, since Aether's discovery mechanism works the same way — devices broadcast their presence invisibly through the air (WiFi) for others to find.

---

## License

Personal / educational project. No license specified yet.
