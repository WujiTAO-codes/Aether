"""
transfer.py — TCP file sending/receiving, wrapped in TLS.
"""

import socket
import ssl
import threading
import json
import os
import hashlib

from identity import extract_public_key_from_der_cert

TCP_PORT = 54546
RECEIVED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received")

MAX_HEADER_LEN = 64 * 1024
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 30
MAX_CONCURRENT_CONNECTIONS = 5
CHUNK_SIZE = 4096

os.makedirs(RECEIVED_DIR, exist_ok=True)

_active_connections = 0
_active_connections_lock = threading.Lock()


def _make_ssl_context(identity, is_server: bool) -> ssl.SSLContext:
    cert_path, key_path = identity.get_cert_and_key_paths()

    if is_server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context


def _recv_exact(sock, num_bytes: int) -> bytes:
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = sock.recv(min(remaining, CHUNK_SIZE))
        if not chunk:
            raise ConnectionError("Connection closed before expected data was received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _sanitize_filename(raw_filename: str) -> str:
    basename = os.path.basename(raw_filename)

    if not basename or basename in (".", ".."):
        raise ValueError("Invalid filename")

    safe_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._- "
    )
    if not all(c in safe_chars for c in basename):
        raise ValueError("Filename contains disallowed characters")

    return basename


def _resolve_safe_path(filename: str) -> str:
    candidate = os.path.join(RECEIVED_DIR, filename)
    resolved = os.path.realpath(candidate)
    received_real = os.path.realpath(RECEIVED_DIR)

    if not resolved.startswith(received_real + os.sep) and resolved != received_real:
        raise ValueError("Resolved path escapes the received/ directory")

    return resolved


def send_file(identity, target_ip: str, target_port: int, expected_public_key: str,
              file_path: str, progress_callback=None) -> dict:
    if not os.path.isfile(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}

    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        return {"success": False, "error": "File exceeds maximum allowed size"}

    filename = os.path.basename(file_path)

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

    try:
        raw_sock.connect((target_ip, target_port))

        context = _make_ssl_context(identity, is_server=False)
        tls_sock = context.wrap_socket(raw_sock, server_hostname=None)

        peer_cert_der = tls_sock.getpeercert(binary_form=True)
        peer_public_key = extract_public_key_from_der_cert(peer_cert_der)
        if peer_public_key != expected_public_key:
            tls_sock.close()
            return {
                "success": False,
                "error": "SECURITY: TLS peer identity does not match the trusted "
                         "device from discovery. Possible interception. Transfer aborted."
            }

        metadata = {
            "filename": filename,
            "filesize": file_size,
            "sha256": file_hash,
        }
        metadata_bytes = json.dumps(metadata).encode("utf-8")
        tls_sock.sendall(len(metadata_bytes).to_bytes(4, "big"))
        tls_sock.sendall(metadata_bytes)

        response = tls_sock.recv(1)
        if response != b"1":
            tls_sock.close()
            return {"success": False, "error": "Receiver rejected the transfer"}

        bytes_sent = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                tls_sock.sendall(chunk)
                bytes_sent += len(chunk)
                if progress_callback:
                    progress_callback(bytes_sent, file_size)

        tls_sock.close()
        return {"success": True, "bytes_sent": bytes_sent}

    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def _handle_client_connection(tls_sock, source_ip: str, on_incoming_request=None):
    try:
        tls_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

        header_len_bytes = _recv_exact(tls_sock, 4)
        header_len = int.from_bytes(header_len_bytes, "big")

        if header_len <= 0 or header_len > MAX_HEADER_LEN:
            tls_sock.close()
            return

        header_bytes = _recv_exact(tls_sock, header_len)

        try:
            metadata = json.loads(header_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            tls_sock.close()
            return

        if not isinstance(metadata, dict):
            tls_sock.close()
            return
        required = ["filename", "filesize", "sha256"]
        if not all(k in metadata for k in required):
            tls_sock.close()
            return
        if not isinstance(metadata["filesize"], int) or metadata["filesize"] <= 0:
            tls_sock.close()
            return
        if metadata["filesize"] > MAX_FILE_SIZE:
            tls_sock.close()
            return

        try:
            safe_filename = _sanitize_filename(metadata["filename"])
            write_path = _resolve_safe_path(safe_filename)
        except ValueError:
            tls_sock.close()
            return

        if on_incoming_request:
            accepted = on_incoming_request(metadata, source_ip)
        else:
            accepted = False

        tls_sock.sendall(b"1" if accepted else b"0")
        if not accepted:
            tls_sock.close()
            return

        sha256 = hashlib.sha256()
        bytes_received = 0
        target_size = metadata["filesize"]

        temp_path = write_path + ".part"

        with open(temp_path, "wb") as f:
            while bytes_received < target_size:
                remaining = target_size - bytes_received
                chunk = tls_sock.recv(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ConnectionError("Connection closed before file fully received")
                f.write(chunk)
                sha256.update(chunk)
                bytes_received += len(chunk)

        if sha256.hexdigest() != metadata["sha256"]:
            os.remove(temp_path)
            print("[transfer] Integrity check FAILED for " + safe_filename + " -- file discarded")
            return

        os.rename(temp_path, write_path)
        print("[transfer] Received and verified: " + safe_filename + " (" + str(bytes_received) + " bytes)")

    except Exception as e:
        print("[transfer] Error handling connection from " + str(source_ip) + ": " + str(e))
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass


def server_thread(identity, stop_event: threading.Event, on_incoming_request=None):
    global _active_connections

    context = _make_ssl_context(identity, is_server=True)

    raw_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server_sock.bind(("", TCP_PORT))
    raw_server_sock.listen(5)
    raw_server_sock.settimeout(1.0)

    while not stop_event.is_set():
        try:
            client_sock, (source_ip, _port) = raw_server_sock.accept()
        except socket.timeout:
            continue
        except Exception as e:
            print("[transfer] server accept error (non-fatal): " + str(e))
            continue

        with _active_connections_lock:
            if _active_connections >= MAX_CONCURRENT_CONNECTIONS:
                client_sock.close()
                continue
            _active_connections += 1

        def handle(sock=client_sock, ip=source_ip):
            global _active_connections
            try:
                tls_sock = context.wrap_socket(sock, server_side=True)
                _handle_client_connection(tls_sock, ip, on_incoming_request)
            except Exception as e:
                print("[transfer] TLS handshake error from " + str(ip) + ": " + str(e))
            finally:
                with _active_connections_lock:
                    _active_connections -= 1

        threading.Thread(target=handle, daemon=True).start()

    raw_server_sock.close()


def start_server(identity, on_incoming_request=None) -> threading.Event:
    stop_event = threading.Event()
    threading.Thread(
        target=server_thread,
        args=(identity, stop_event, on_incoming_request),
        daemon=True,
    ).start()
    return stop_event
