"""
utils.py — small shared helpers used across the project.
No security-sensitive logic lives here; just plumbing.
"""

import socket


def get_local_ip():
    """
    Find this machine's LAN IP address (e.g. 192.168.1.5).

    Trick: we don't actually need to send data anywhere. Opening a UDP
    socket and "connecting" it to a public IP (8.8.8.8) doesn't send
    any packets — it just asks the OS to pick which local network
    interface *would* be used to reach that address, and we read that
    interface's IP off the socket. This works even with no internet
    access, since UDP connect() doesn't perform a handshake.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"  # fallback if machine has no network at all
    finally:
        s.close()
    return ip


def format_size(num_bytes):
    """
    Convert a byte count into a human-readable string.
    e.g. 2456789 -> "2.34 MB"
    """
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"
