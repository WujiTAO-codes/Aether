"""
discovery.py — UDP broadcast/listen logic for finding other Aether
devices on the local network.

SECURITY MODEL FOR THIS FILE:
  - Every ANNOUNCE packet is signed with the sender's private key
    (identity.py). Receivers verify the signature before trusting
    ANYTHING in the packet. A forged or tampered packet is dropped
    silently — the sender never even knows we saw it.
  - NOTE: this only proves "packet integrity + sender controls this
    keypair." It does NOT yet prove the sender is a device you've
    seen before — that's the job of the TOFU trust check in main.py,
    which compares (device_id -> public_key) against history.
  - Rate limiting stops a single source IP from flooding us with
    packets and exhausting memory/CPU.
  - Every parsing step is wrapped in try/except so one malformed or
    malicious packet can NEVER crash the listener thread.
"""

import socket
import threading
import time
import json

from identity import verify

UDP_PORT = 54545
BROADCAST_ADDR = "255.255.255.255"
ANNOUNCE_INTERVAL_SECONDS = 3
DEVICE_TIMEOUT_SECONDS = 10          # remove a device if not heard from in this long
MAX_KNOWN_DEVICES = 200              # hard cap, prevents memory-exhaustion attacks
MAX_PACKETS_PER_IP_PER_WINDOW = 10   # rate limit: max packets...
RATE_LIMIT_WINDOW_SECONDS = 3        # ...per this many seconds, per source IP

# Shared state — the dictionary the CLI (main.py) reads to show
# "devices found nearby." Protected by a lock because the listener
# thread writes to it while the main thread reads it concurrently.
known_devices = {}
_known_devices_lock = threading.Lock()

# Rate-limiting state: source_ip -> list of recent packet timestamps
_packet_timestamps = {}
_rate_limit_lock = threading.Lock()


def _is_rate_limited(source_ip: str) -> bool:
    """
    Returns True if this IP has sent too many packets too quickly.

    Why this matters: without this check, an attacker (or even a
    buggy device) blasting thousands of UDP packets/sec would force
    us to verify a signature on every single one — wasting CPU — and
    could still flood known_devices before the size cap kicks in.
    This check runs BEFORE any signature verification, so flooding
    is cheap to reject.
    """
    now = time.time()
    with _rate_limit_lock:
        timestamps = _packet_timestamps.setdefault(source_ip, [])

        # Drop timestamps older than our rate-limit window
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

        if len(timestamps) >= MAX_PACKETS_PER_IP_PER_WINDOW:
            return True  # too many packets recently — reject this one

        timestamps.append(now)
        return False


def _build_announce_payload(identity, device_name: str, tcp_port: int) -> dict:
    """
    Build the ANNOUNCE packet fields EXCLUDING the signature itself.
    We sign this exact structure, then attach the signature separately.
    Keeping "data we sign" and "the signature" clearly separate avoids
    a subtle bug: you must never include the signature field in the
    data that gets signed, or verification becomes circular/broken.
    """
    return {
        "type": "ANNOUNCE",
        "device_id": identity.device_id,
        "device_name": device_name,
        "tcp_port": tcp_port,
        "public_key": identity.public_key_b64(),
    }


def _canonical_bytes(payload: dict) -> bytes:
    """
    Turn a dict into a deterministic byte string for signing/verifying.

    Why sort_keys=True matters: JSON doesn't guarantee key order.
    If the sender serializes {"a":1,"b":2} and, due to some library
    quirk, the receiver reconstructs it as {"b":2,"a":1}, the raw
    bytes differ even though the DATA is identical — and the
    signature would fail to verify even for a perfectly legitimate
    packet. Sorting keys makes serialization deterministic on both
    ends, so this can never happen.
    """
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def broadcaster_thread(identity, device_name: str, tcp_port: int, stop_event: threading.Event):
    """
    Runs forever (daemon thread): every few seconds, broadcast a
    signed ANNOUNCE packet so other devices on the LAN can find us.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while not stop_event.is_set():
        try:
            payload = _build_announce_payload(identity, device_name, tcp_port)
            data_to_sign = _canonical_bytes(payload)
            payload["signature"] = identity.sign(data_to_sign)

            packet = json.dumps(payload).encode("utf-8")
            sock.sendto(packet, (BROADCAST_ADDR, UDP_PORT))
        except Exception as e:
            # Never let a transient network error kill this thread —
            # just log it (conceptually) and try again next cycle.
            print(f"[discovery] broadcaster error (non-fatal): {e}")

        stop_event.wait(ANNOUNCE_INTERVAL_SECONDS)

    sock.close()


def _handle_incoming_packet(raw_data: bytes, source_ip: str):
    """
    Process a single received UDP packet. This function is the main
    security choke point for discovery — every incoming packet passes
    through here and must survive several checks before it's trusted.
    """
    # --- Check 1: rate limiting (cheapest check, runs first) ---
    if _is_rate_limited(source_ip):
        return  # silently drop, no processing wasted on a flooder

    # --- Check 2: is it even valid JSON? ---
    try:
        packet = json.loads(raw_data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return  # malformed packet — drop silently, don't crash

    # --- Check 3: does it have the fields we require? ---
    required_fields = ["type", "device_id", "device_name", "tcp_port", "public_key", "signature"]
    if not isinstance(packet, dict) or not all(f in packet for f in required_fields):
        return  # incomplete packet — drop

    if packet.get("type") != "ANNOUNCE":
        return  # not a packet type we understand — ignore

    # --- Check 4: signature verification (the core defense) ---
    # Rebuild exactly what should have been signed (everything except
    # the signature field itself), then check the signature against
    # the public_key the packet itself provided.
    signature = packet["signature"]
    payload_without_signature = {k: v for k, v in packet.items() if k != "signature"}
    data_that_should_have_been_signed = _canonical_bytes(payload_without_signature)

    is_valid = verify(
        data_that_should_have_been_signed,
        signature,
        packet["public_key"],
    )
    if not is_valid:
        # Signature doesn't match — either corrupted in transit, or
        # someone is tampering with / forging this packet. Either way,
        # we cannot trust anything in it. Drop it entirely.
        return

    # --- Passed all checks: safe to record this device ---
    with _known_devices_lock:
        # Enforce the size cap BEFORE adding a new entry, so a flood
        # of distinct fake device_ids can't grow this dict unbounded.
        if packet["device_id"] not in known_devices and len(known_devices) >= MAX_KNOWN_DEVICES:
            # Evict the least-recently-seen device to make room.
            oldest_id = min(known_devices, key=lambda k: known_devices[k]["last_seen"])
            del known_devices[oldest_id]

        known_devices[packet["device_id"]] = {
            "name": packet["device_name"],
            "ip": source_ip,
            "tcp_port": packet["tcp_port"],
            "public_key": packet["public_key"],
            "last_seen": time.time(),
        }


def listener_thread(stop_event: threading.Event):
    """
    Runs forever (daemon thread): listens for ANNOUNCE packets from
    other devices and updates known_devices with verified entries.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", UDP_PORT))
    sock.settimeout(1.0)  # so we periodically check stop_event, not block forever

    while not stop_event.is_set():
        try:
            raw_data, (source_ip, _source_port) = sock.recvfrom(4096)
            _handle_incoming_packet(raw_data, source_ip)
        except socket.timeout:
            continue  # normal — just means no packet arrived this second
        except Exception as e:
            # Catch-all: a single weird/malicious packet must never be
            # able to kill this thread. Log and keep listening.
            print(f"[discovery] listener error (non-fatal): {e}")

    sock.close()


def cleanup_thread(stop_event: threading.Event):
    """
    Runs forever (daemon thread): periodically removes devices we
    haven't heard from recently (they've likely left the network).
    """
    while not stop_event.is_set():
        now = time.time()
        with _known_devices_lock:
            stale_ids = [
                device_id
                for device_id, info in known_devices.items()
                if now - info["last_seen"] > DEVICE_TIMEOUT_SECONDS
            ]
            for device_id in stale_ids:
                del known_devices[device_id]

        stop_event.wait(2)  # check every 2 seconds


def start_discovery(identity, device_name: str, tcp_port: int) -> threading.Event:
    """
    Convenience function: starts all three discovery threads as
    daemons and returns a stop_event the caller can use to shut
    them down cleanly on exit.
    """
    stop_event = threading.Event()

    threading.Thread(
        target=broadcaster_thread,
        args=(identity, device_name, tcp_port, stop_event),
        daemon=True,
    ).start()

    threading.Thread(
        target=listener_thread,
        args=(stop_event,),
        daemon=True,
    ).start()

    threading.Thread(
        target=cleanup_thread,
        args=(stop_event,),
        daemon=True,
    ).start()

    return stop_event
