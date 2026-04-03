"""
tunnel.py — Secure IP tunnel over a text-based messaging channel.

Packets are encrypted (X25519 + ChaCha20-Poly1305) and encoded as plain
ASCII text messages so they can be sent through any messenger (Rocket.Chat,
Matrix, XMPP, SMS, …).

Wire your messenger by replacing send() at the bottom of this file, then
feed incoming messages into receive().

Usage (loopback self-test, no root needed):
    python tunnel.py --loopback
"""

import argparse
import base64
import collections
import logging
import os
import struct
import sys
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

TUN_NAME  = "tun-txtunnel"
TUN_MTU   = 1400
LOCAL_IP  = os.environ.get("TUN_LOCAL_IP", "10.0.0.1")
PEER_IP   = os.environ.get("TUN_PEER_IP",  "10.0.0.2")
NETMASK   = "255.255.255.252"   # /30

HKDF_INFO  = b"text-tunnel-v1"
MAX_MSG_LEN = 900

# Header: "PKT:SSSS:II/TT:" = 15 chars
# Available base64: 900 - 15 = 885 chars → floor(885/4)*3 = 663 raw bytes
# Each blob = 12-byte nonce + ciphertext + 16-byte tag  → max plaintext = 635
CHUNK_PLAINTEXT = 635

SEQ_MAX                  = 0xFFFF
REASSEMBLY_TIMEOUT       = 30.0   # seconds
REPLAY_WINDOW_SIZE       = 1000
PRE_HANDSHAKE_BUFFER_MAX = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_b64decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


# ---------------------------------------------------------------------------
# CryptoLayer
# ---------------------------------------------------------------------------

class CryptoLayer:
    def __init__(self) -> None:
        self._private_key: X25519PrivateKey | None = None
        self._public_key:  X25519PublicKey  | None = None
        self._symmetric_key: bytes | None = None

    def generate_keypair(self) -> None:
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()

    def get_public_key_b64(self) -> str:
        return base64.urlsafe_b64encode(self._public_key.public_bytes_raw()).decode()

    def derive_shared_key(self, peer_pubkey_b64: str) -> None:
        raw = _safe_b64decode(peer_pubkey_b64)
        if len(raw) != 32:
            raise ValueError(f"Bad peer pubkey length: {len(raw)}")
        peer_key      = X25519PublicKey.from_public_bytes(raw)
        shared_secret = self._private_key.exchange(peer_key)
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=HKDF_INFO)
        self._symmetric_key = hkdf.derive(shared_secret)

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        return ChaCha20Poly1305(self._symmetric_key).encrypt(nonce, plaintext, None)

    def decrypt(self, ciphertext_with_tag: bytes, nonce: bytes) -> bytes:
        return ChaCha20Poly1305(self._symmetric_key).decrypt(nonce, ciphertext_with_tag, None)


# ---------------------------------------------------------------------------
# Framer
# ---------------------------------------------------------------------------

class Framer:
    def __init__(self) -> None:
        self._reassembly: dict[tuple[int, int], dict] = {}
        self._lock = threading.Lock()

    # --- encode ---

    def encode_hello(self, pubkey_b64: str) -> str:
        return f"HELLO:0:00/01:{pubkey_b64}"

    def encode_pkt_chunk(self, seq: int, idx: int, total: int, blob_b64: str) -> str:
        return f"PKT:{seq:04X}:{idx:02X}/{total:02X}:{blob_b64}"

    # --- decode ---

    def decode(self, message: str) -> dict | None:
        parts = message.split(":", 3)
        if len(parts) != 4:
            log.warning("Malformed message (bad field count): %r", message[:80])
            return None
        msg_type, seq_field, idx_total, payload = parts
        msg_type = msg_type.upper()
        if msg_type not in ("HELLO", "PKT"):
            log.warning("Unknown message type: %r", msg_type)
            return None
        try:
            seq = int(seq_field, 16)
        except ValueError:
            log.warning("Bad seq field: %r", seq_field)
            return None
        slash = idx_total.find("/")
        if slash == -1:
            log.warning("Bad idx/total field: %r", idx_total)
            return None
        try:
            idx   = int(idx_total[:slash], 16)
            total = int(idx_total[slash + 1:], 16)
        except ValueError:
            log.warning("Bad idx/total values: %r", idx_total)
            return None
        if total < 1 or idx >= total or total > 0xFF:
            log.warning("Invalid chunk params idx=%d total=%d", idx, total)
            return None
        return {"type": msg_type, "seq": seq, "idx": idx, "total": total, "payload": payload}

    # --- reassembly ---

    def add_chunk(self, seq: int, idx: int, total: int, payload: str) -> list[str] | None:
        with self._lock:
            self._evict_expired()
            key = (seq, total)
            if key not in self._reassembly:
                self._reassembly[key] = {"chunks": {}, "timestamp": time.monotonic()}
            self._reassembly[key]["chunks"][idx] = payload
            if len(self._reassembly[key]["chunks"]) == total:
                chunks = self._reassembly.pop(key)["chunks"]
                return [chunks[i] for i in range(total)]
        return None

    def _evict_expired(self) -> None:
        now     = time.monotonic()
        expired = [k for k, v in self._reassembly.items()
                   if now - v["timestamp"] > REASSEMBLY_TIMEOUT]
        for k in expired:
            log.warning("Reassembly timeout seq=%04X total=%d", k[0], k[1])
            del self._reassembly[k]


# ---------------------------------------------------------------------------
# TUN interface  (Linux: pytun → ioctl fallback | macOS: utun built-in)
# ---------------------------------------------------------------------------

class TUNInterface:
    _AF_INET_BE = struct.pack("!I", 2)   # macOS utun family header

    def __init__(self, on_packet) -> None:
        self._on_packet  = on_packet
        self._tun        = None
        self._tun_fd     = -1
        self._use_pytun  = False
        self._use_utun   = False
        self._running    = threading.Event()
        self._write_lock = threading.Lock()

    def open(self) -> None:
        if sys.platform == "darwin":
            self._open_utun()
        else:
            try:
                import pytun  # type: ignore
                self._open_pytun(pytun)
                self._use_pytun = True
            except ImportError:
                self._open_ioctl()

    def _open_pytun(self, pytun) -> None:
        tun = pytun.TunTapDevice(name=TUN_NAME, flags=pytun.IFF_TUN)
        tun.addr    = LOCAL_IP
        tun.netmask = NETMASK
        tun.mtu     = TUN_MTU
        tun.up()
        self._tun = tun
        log.info("TUN up via pytun: %s  addr=%s", TUN_NAME, LOCAL_IP)

    def _open_ioctl(self) -> None:
        import fcntl
        import socket as _socket

        TUNSETIFF      = 0x400454ca
        IFF_TUN        = 0x0001;  IFF_NO_PI   = 0x1000
        SIOCSIFADDR    = 0x8916;  SIOCSIFNETMASK = 0x891c
        SIOCSIFMTU     = 0x8922;  SIOCGIFFLAGS   = 0x8913
        SIOCSIFFLAGS   = 0x8914;  IFF_UP         = 0x0001
        IFF_RUNNING    = 0x0040;  IFNAMSIZ       = 16

        name_b = TUN_NAME.encode()[:IFNAMSIZ].ljust(IFNAMSIZ, b"\x00")
        fd = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(fd, TUNSETIFF,
                    struct.pack("16sH14s", name_b, IFF_TUN | IFF_NO_PI, b"\x00" * 14))

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            def _ifreq_addr(ip):
                sa = struct.pack("!HH4s8s", _socket.AF_INET, 0,
                                 _socket.inet_aton(ip), b"\x00" * 8)
                return name_b + sa
            fcntl.ioctl(sock, SIOCSIFADDR,    _ifreq_addr(LOCAL_IP))
            fcntl.ioctl(sock, SIOCSIFNETMASK, _ifreq_addr(NETMASK))
            fcntl.ioctl(sock, SIOCSIFMTU,
                        struct.pack("16si12s", name_b, TUN_MTU, b"\x00" * 12))
            res   = fcntl.ioctl(sock, SIOCGIFFLAGS,
                                 struct.pack("16sH14s", name_b, 0, b"\x00" * 14))
            flags = struct.unpack("16sH14s", res)[1] | IFF_UP | IFF_RUNNING
            fcntl.ioctl(sock, SIOCSIFFLAGS,
                        struct.pack("16sH14s", name_b, flags, b"\x00" * 14))
        finally:
            sock.close()

        self._tun = self._tun_fd = fd
        log.info("TUN up via ioctl: %s  addr=%s", TUN_NAME, LOCAL_IP)

    def _open_utun(self) -> None:
        import fcntl
        import socket as _socket
        import subprocess

        AF_SYSTEM         = 32
        SYSPROTO_CONTROL  = 2
        AF_SYS_CONTROL    = 2
        UTUN_CONTROL_NAME = b"com.apple.net.utun_control"
        UTUN_OPT_IFNAME   = 2
        CTLIOCGINFO       = 0xC0644E03

        sock = _socket.socket(AF_SYSTEM, _socket.SOCK_DGRAM, SYSPROTO_CONTROL)
        ctl_info = bytearray(struct.pack("I96s", 0, UTUN_CONTROL_NAME))
        fcntl.ioctl(sock.fileno(), CTLIOCGINFO, ctl_info)  # modifies ctl_info in place
        ctl_id   = struct.unpack_from("I", ctl_info)[0]

        # Python's PF_SYSTEM socket expects (ctl_id, unit) — unit=0 = auto-assign
        sock.connect((ctl_id, 0))

        ifname = sock.getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 32)
        ifname = ifname.rstrip(b"\x00").decode()

        subprocess.check_call(
            ["ifconfig", ifname, LOCAL_IP, PEER_IP,
             "netmask", NETMASK, "mtu", str(TUN_MTU), "up"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        self._tun      = sock
        self._tun_fd   = sock.fileno()
        self._use_utun = True
        log.info("TUN up via utun: %s  addr=%s", ifname, LOCAL_IP)

    def start(self) -> None:
        self._running.set()
        threading.Thread(target=self._read_loop, daemon=True, name="tun-read").start()

    def _read_loop(self) -> None:
        while self._running.is_set():
            try:
                if self._use_pytun:
                    pkt = self._tun.read(TUN_MTU)
                else:
                    raw = os.read(self._tun_fd, TUN_MTU + 4)
                    pkt = raw[4:] if self._use_utun else raw
            except OSError as e:
                log.error("TUN read: %s", e)
                time.sleep(0.01)
                continue
            if pkt:
                self._on_packet(pkt)

    def write(self, packet: bytes) -> None:
        with self._write_lock:
            try:
                if self._use_pytun:
                    self._tun.write(packet)
                elif self._use_utun:
                    os.write(self._tun_fd, self._AF_INET_BE + packet)
                else:
                    os.write(self._tun_fd, packet)
            except OSError as e:
                log.warning("TUN write: %s", e)

    def close(self) -> None:
        self._running.clear()
        if self._tun is not None:
            try:
                if self._use_pytun:
                    self._tun.close()
                elif self._use_utun:
                    self._tun.close()
                else:
                    os.close(self._tun_fd)
            except OSError:
                pass
            self._tun = None


# ---------------------------------------------------------------------------
# Tunnel
# ---------------------------------------------------------------------------

class Tunnel:
    def __init__(self) -> None:
        self._crypto  = CryptoLayer()
        self._framer  = Framer()
        self._tun     = TUNInterface(on_packet=self._on_tun_packet)

        self._seq      = 0
        self._seq_lock = threading.Lock()

        self._handshake_done = threading.Event()

        self._pre_buf      : list[bytes] = []
        self._pre_buf_lock = threading.Lock()

        self._replay_window: collections.deque = collections.deque(
            maxlen=REPLAY_WINDOW_SIZE)
        self._replay_lock = threading.Lock()

    # --- lifecycle ---

    def start(self) -> None:
        log.info("Tunnel starting")
        self._crypto.generate_keypair()
        self._tun.open()
        self._tun.start()
        send(self._framer.encode_hello(self._crypto.get_public_key_b64()))
        log.info("HELLO sent")

    def stop(self) -> None:
        log.info("Tunnel stopping")
        self._tun.close()

    # --- TX ---

    def _next_seq(self) -> int:
        with self._seq_lock:
            seq = self._seq
            self._seq = (self._seq + 1) & SEQ_MAX
        return seq

    def _on_tun_packet(self, raw: bytes) -> None:
        if not self._handshake_done.is_set():
            with self._pre_buf_lock:
                if len(self._pre_buf) < PRE_HANDSHAKE_BUFFER_MAX:
                    self._pre_buf.append(raw)
                else:
                    log.warning("Pre-handshake buffer full, dropping packet")
            return
        self._send_packet(raw)

    def _send_packet(self, raw: bytes) -> None:
        chunks = [raw[i:i + CHUNK_PLAINTEXT] for i in range(0, len(raw), CHUNK_PLAINTEXT)]
        if not chunks:
            return
        seq   = self._next_seq()
        total = len(chunks)
        for idx, plain in enumerate(chunks):
            nonce    = os.urandom(12)
            ct       = self._crypto.encrypt(plain, nonce)
            blob_b64 = base64.urlsafe_b64encode(nonce + ct).decode()
            send(self._framer.encode_pkt_chunk(seq, idx, total, blob_b64))

    # --- RX ---

    def receive(self, message: str) -> None:
        parsed = self._framer.decode(message)
        if parsed is None:
            return
        if parsed["type"] == "HELLO":
            if self._handshake_done.is_set():
                log.warning("Duplicate HELLO, ignoring")
                return
            self._handle_hello(parsed["payload"])
        elif parsed["type"] == "PKT":
            self._handle_pkt(parsed)

    def _handle_hello(self, peer_pubkey_b64: str) -> None:
        if self._handshake_done.is_set():
            # Peer re-sent its HELLO (e.g. it joined late and missed ours).
            # Re-send our HELLO so it can complete the handshake.
            log.info("Duplicate HELLO — re-sending our HELLO so peer can complete")
            send(self._framer.encode_hello(self._crypto.get_public_key_b64()))
            return
        try:
            self._crypto.derive_shared_key(peer_pubkey_b64)
        except Exception as e:
            log.warning("HELLO key derivation failed: %s", e)
            return
        self._handshake_done.set()
        log.info("Handshake complete")
        with self._pre_buf_lock:
            buffered, self._pre_buf = list(self._pre_buf), []
        if buffered:
            log.info("Flushing %d pre-handshake packets", len(buffered))
        for pkt in buffered:
            self._send_packet(pkt)

    def _handle_pkt(self, parsed: dict) -> None:
        if not self._handshake_done.is_set():
            log.warning("PKT before handshake, dropping")
            return
        assembled = self._framer.add_chunk(
            parsed["seq"], parsed["idx"], parsed["total"], parsed["payload"])
        if assembled is None:
            return

        plaintext_parts: list[bytes] = []
        for blob_b64 in assembled:
            try:
                blob = _safe_b64decode(blob_b64)
            except Exception as e:
                log.warning("Base64 decode error: %s", e)
                return
            if len(blob) < 28:
                log.warning("Blob too short (%d bytes)", len(blob))
                return
            nonce, ct = blob[:12], blob[12:]
            replay_key = (parsed["seq"], nonce)
            with self._replay_lock:
                if replay_key in self._replay_window:
                    log.warning("Replay detected seq=%04X, dropping", parsed["seq"])
                    return
            try:
                plaintext = self._crypto.decrypt(ct, nonce)
            except InvalidTag:
                log.warning("MAC fail seq=%04X, dropping", parsed["seq"])
                return
            with self._replay_lock:
                self._replay_window.append(replay_key)
            plaintext_parts.append(plaintext)

        self._tun.write(b"".join(plaintext_parts))


# ---------------------------------------------------------------------------
# Module-level wiring
# ---------------------------------------------------------------------------

tunnel = Tunnel()


def receive(message: str) -> None:
    """Called externally when a text message arrives from the messenger."""
    tunnel.receive(message)


def send(message: str) -> None:
    """
    Called by the tunnel to transmit a text message via the messenger.
    Replace this with your actual messenger transport, e.g.:

        import tunnel
        tunnel.send = rocketchat_transport.send
        tunnel.tunnel.start()
    """
    raise NotImplementedError(
        "Wire send() to your messaging channel.\n"
        "Example:  import tunnel; tunnel.send = my_send_fn"
    )


# ---------------------------------------------------------------------------
# Loopback self-test  (no root, no TUN, no messenger needed)
# ---------------------------------------------------------------------------

def _run_loopback_test() -> None:
    logging.getLogger().setLevel(logging.DEBUG)
    log.info("=== loopback test ===")

    alice = Tunnel()
    bob   = Tunnel()
    _cur  = [alice]

    def _loopback_send(msg: str) -> None:
        (_cur[0] is alice and bob or alice).receive(msg)

    global send
    send = _loopback_send

    alice._crypto.generate_keypair()
    bob._crypto.generate_keypair()

    _cur[0] = alice
    alice.receive(bob._framer.encode_hello(bob._crypto.get_public_key_b64()))
    _cur[0] = bob
    bob.receive(alice._framer.encode_hello(alice._crypto.get_public_key_b64()))

    assert alice._handshake_done.is_set(), "Alice handshake failed"
    assert bob._handshake_done.is_set(),   "Bob handshake failed"
    log.info("Handshake OK")

    received: list[bytes] = []
    bob._tun.write = lambda pkt: received.append(pkt)

    # small packet
    payload = b"\x45\x00" + b"\xAB" * 100
    _cur[0] = alice
    alice._send_packet(payload)
    assert received == [payload], "Small packet mismatch"
    log.info("Small packet PASSED (%d bytes)", len(payload))

    # large packet — 3 chunks
    large = os.urandom(TUN_MTU)
    received.clear()
    alice._send_packet(large)
    assert received == [large], "Large packet mismatch"
    log.info("Large packet PASSED (%d bytes, 3 chunks)", len(large))

    # replay
    nonce  = os.urandom(12)
    ct     = bob._crypto.encrypt(b"\x00" * 10, nonce)
    b64    = base64.urlsafe_b64encode(nonce + ct).decode()
    parsed = {"seq": 0x1234, "idx": 0, "total": 1, "payload": b64}
    received.clear()
    bob._handle_pkt(parsed)
    assert len(received) == 1, "First delivery failed"
    received.clear()
    bob._handle_pkt(parsed)
    assert len(received) == 0, "Replay not blocked"
    log.info("Replay protection PASSED")

    print("\n=== ALL LOOPBACK TESTS PASSED ===\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--loopback", action="store_true",
                        help="Run self-test (no root/TUN/messenger needed)")
    args = parser.parse_args()
    if args.loopback:
        _run_loopback_test()
    else:
        print("Wire send() then call tunnel.tunnel.start()\n"
              "Self-test: python tunnel.py --loopback")
