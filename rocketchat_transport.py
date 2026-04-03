"""
rocketchat_transport.py — Rocket.Chat transport for tunnel.py

Sends tunnel messages as text posts to a Rocket.Chat channel.
Receives tunnel messages by subscribing to that channel via the
Rocket.Chat Realtime WebSocket API (DDP protocol).

Only messages that start with "HELLO:" or "PKT:" are fed into the tunnel;
all other channel traffic is ignored.

Auth — choose ONE of the two methods via environment variables:

  Method A — Personal Access Token (recommended):
    RC_URL         Rocket.Chat server, e.g. https://chat.example.com
    RC_AUTH_TOKEN  Personal access token  (My Account → Personal Access Tokens)
    RC_USER_ID     Your user ID           (shown next to the token)
    RC_USERNAME    Your username          (used to skip echo of own messages)
    RC_CHANNEL     Channel name without #, e.g. tunnel

  Method B — Username + Password:
    RC_URL         Rocket.Chat server
    RC_USERNAME    Username
    RC_PASSWORD    Password
    RC_CHANNEL     Channel name without #

  Token auth takes priority if RC_AUTH_TOKEN is set.

Usage:
    import rocketchat_transport
    rocketchat_transport.start()   # connects WS, sets tunnel.send
    tunnel.tunnel.start()          # opens TUN, sends HELLO

Or run standalone for a connection test (no TUN):
    python rocketchat_transport.py
"""

import hashlib
import json
import logging
import os
import ssl
import threading
import time
import urllib3
import uuid

import requests
import websocket   # pip install websocket-client

import tunnel as _tunnel

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (from environment)
# ---------------------------------------------------------------------------

RC_URL        = os.environ.get("RC_URL",        "").rstrip("/")
if RC_URL and not RC_URL.startswith(("http://", "https://")):
    RC_URL = "https://" + RC_URL
RC_USERNAME   = os.environ.get("RC_USERNAME",   "")
RC_PASSWORD   = os.environ.get("RC_PASSWORD",   "")
RC_VERIFY_SSL = os.environ.get("RC_VERIFY_SSL", "false").lower() not in ("0", "false", "no")

# Suppress InsecureRequestWarning when SSL verification is disabled
if not RC_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
RC_AUTH_TOKEN = os.environ.get("RC_AUTH_TOKEN", "")  # Personal Access Token
RC_USER_ID    = os.environ.get("RC_USER_ID",    "")  # paired with RC_AUTH_TOKEN
RC_CHANNEL    = os.environ.get("RC_CHANNEL",    "tunnel")

# Token auth takes priority when both RC_AUTH_TOKEN and RC_USER_ID are set
_USE_TOKEN_AUTH = bool(RC_AUTH_TOKEN and RC_USER_ID)

# How long to wait between reconnect attempts
RECONNECT_DELAY = 5   # seconds


# ---------------------------------------------------------------------------
# RocketChatTransport
# ---------------------------------------------------------------------------

class RocketChatTransport:
    def __init__(self) -> None:
        self._ws           = None
        self._auth_token   = None
        self._user_id      = None
        self._room_id      = None
        self._connected    = threading.Event()
        self._ws_thread    = None
        self._sent_ids: set[str] = set()   # IDs of messages we posted — skip on RX
        self._sub_id:   str      = ""      # DDP subscription ID

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Connect to Rocket.Chat and wire tunnel.send → self.send."""
        self._validate_config()
        if _USE_TOKEN_AUTH:
            self._auth_token = RC_AUTH_TOKEN
            self._user_id    = RC_USER_ID
            log.info("Using Personal Access Token auth (user_id=%s)", RC_USER_ID)
        else:
            self._rest_login()
        self._room_id = self._resolve_room(RC_CHANNEL)
        log.info("Room '%s' resolved to id=%s", RC_CHANNEL, self._room_id)

        self._ws_thread = threading.Thread(
            target=self._ws_loop, daemon=True, name="rc-ws"
        )
        self._ws_thread.start()

        if not self._connected.wait(timeout=20):
            raise TimeoutError("WebSocket did not connect within 20s")

        # Wire tunnel.send to go through Rocket.Chat
        _tunnel.send = self.send
        log.info("Rocket.Chat transport ready — channel #%s", RC_CHANNEL)

    def send(self, message: str) -> None:
        """Post a tunnel message to the Rocket.Chat channel (REST API)."""
        try:
            resp = requests.post(
                f"{RC_URL}/api/v1/chat.sendMessage",
                headers={
                    "X-Auth-Token": self._auth_token,
                    "X-User-Id":    self._user_id,
                    "Content-Type": "application/json",
                },
                json={"message": {"rid": self._room_id, "msg": message}},
                timeout=10,
                verify=RC_VERIFY_SSL,
            )
            if resp.ok:
                msg_id = resp.json().get("message", {}).get("_id")
                if msg_id:
                    self._sent_ids.add(msg_id)
            else:
                log.warning("RC send failed %d: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.warning("RC send error: %s", e)

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------

    def _validate_config(self) -> None:
        if not RC_URL:
            raise EnvironmentError("RC_URL is not set.")
        if _USE_TOKEN_AUTH:
            # Token auth: need token + user_id (username optional but recommended)
            return
        # Password auth: need username + password
        missing = [k for k, v in
                   [("RC_USERNAME", RC_USERNAME), ("RC_PASSWORD", RC_PASSWORD)]
                   if not v]
        if missing:
            raise EnvironmentError(
                f"Missing environment variables: {', '.join(missing)}\n"
                "Either set RC_AUTH_TOKEN + RC_USER_ID (token auth)\n"
                "or set RC_USERNAME + RC_PASSWORD (password auth)."
            )

    def _rest_login(self) -> None:
        resp = requests.post(
            f"{RC_URL}/api/v1/login",
            json={"username": RC_USERNAME, "password": RC_PASSWORD},
            timeout=10,
            verify=RC_VERIFY_SSL,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        self._auth_token = data["authToken"]
        self._user_id    = data["userId"]
        log.info("Logged in to Rocket.Chat as '%s'", RC_USERNAME)

    def _resolve_room(self, channel_name: str) -> str:
        """Return the room _id for a channel name (public or private)."""
        headers = {
            "X-Auth-Token": self._auth_token,
            "X-User-Id":    self._user_id,
        }

        # Try public channel first
        resp = requests.get(
            f"{RC_URL}/api/v1/channels.info",
            headers=headers,
            params={"roomName": channel_name},
            timeout=10,
            verify=RC_VERIFY_SSL,
        )
        if resp.ok:
            return resp.json()["channel"]["_id"]

        # Try private group
        resp2 = requests.get(
            f"{RC_URL}/api/v1/groups.info",
            headers=headers,
            params={"roomName": channel_name},
            timeout=10,
            verify=RC_VERIFY_SSL,
        )
        if resp2.ok:
            return resp2.json()["group"]["_id"]

        # Neither worked — show both errors clearly
        raise RuntimeError(
            f"Could not resolve channel '{channel_name}'.\n"
            f"  channels.info → {resp.status_code}: {resp.text[:200]}\n"
            f"  groups.info   → {resp2.status_code}: {resp2.text[:200]}\n"
            "Make sure the channel exists and your user has access to it."
        )

    # ------------------------------------------------------------------
    # WebSocket / DDP
    # ------------------------------------------------------------------

    def _ws_url(self) -> str:
        base = RC_URL.replace("https://", "wss://").replace("http://", "ws://")
        return f"{base}/websocket"

    def _ws_loop(self) -> None:
        """Run the WebSocket connection; reconnect automatically on failure."""
        while True:
            try:
                log.info("Connecting to %s", self._ws_url())
                ws = websocket.WebSocketApp(
                    self._ws_url(),
                    header={
                        "Origin": RC_URL,
                    },
                    on_open    = self._on_ws_open,
                    on_message = self._on_ws_message,
                    on_error   = self._on_ws_error,
                    on_close   = self._on_ws_close,
                )
                self._ws = ws
                # Force HTTP/1.1 via ALPN — WebSocket upgrade requires HTTP/1.1
                # but some nginx/openresty setups negotiate HTTP/2 by default.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE if not RC_VERIFY_SSL else ssl.CERT_REQUIRED
                ctx.set_alpn_protocols(["http/1.1"])
                ws.run_forever(
                    ping_interval=30,
                    ping_timeout=10,
                    sslopt={"context": ctx},
                )
            except Exception as e:
                log.warning("WebSocket loop error: %s", e)
            log.info("Reconnecting in %ds…", RECONNECT_DELAY)
            self._connected.clear()
            time.sleep(RECONNECT_DELAY)

    def _send_ddp(self, obj: dict) -> None:
        if self._ws:
            self._ws.send(json.dumps(obj))

    def _on_ws_open(self, ws) -> None:
        log.debug("WS open — sending DDP connect")
        self._send_ddp({
            "msg":     "connect",
            "version": "1",
            "support": ["1"],
        })

    def _on_ws_message(self, ws, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return

        kind = msg.get("msg")

        # DDP ping
        if kind == "ping":
            self._send_ddp({"msg": "pong"})
            return

        # DDP connected → log in via DDP
        if kind == "connected":
            log.debug("DDP connected — logging in")
            if _USE_TOKEN_AUTH:
                # Resume session using Personal Access Token
                params = [{"resume": self._auth_token}]
            else:
                pw_hash = hashlib.sha256(RC_PASSWORD.encode()).hexdigest()
                params = [{
                    "user":     {"username": RC_USERNAME},
                    "password": {"digest": pw_hash, "algorithm": "sha-256"},
                }]
            self._send_ddp({
                "msg":    "method",
                "id":     "login",
                "method": "login",
                "params": params,
            })
            return

        # Login result → subscribe to room messages
        if kind == "result" and msg.get("id") == "login":
            if "error" in msg:
                log.error("DDP login failed: %s", msg["error"])
                return
            log.info("DDP login OK")
            self._sub_id = str(uuid.uuid4())
            self._send_ddp({
                "msg":    "sub",
                "id":     self._sub_id,
                "name":   "stream-room-messages",
                "params": [self._room_id, False],
            })
            return

        # Subscription confirmed → now safe to signal ready and (re)send HELLO
        if kind == "ready" and self._sub_id in msg.get("subs", []):
            log.info("Subscription confirmed")
            self._connected.set()
            # Re-send HELLO so the peer gets it now that we're subscribed
            if _tunnel.tunnel._crypto._public_key is not None:
                hello = _tunnel.tunnel._framer.encode_hello(
                    _tunnel.tunnel._crypto.get_public_key_b64()
                )
                self.send(hello)
                log.info("HELLO re-sent after subscription confirmed")
            return

        # Incoming room message
        if kind == "changed" and msg.get("collection") == "stream-room-messages":
            try:
                args    = msg["fields"]["args"]
                rc_msg  = args[0]
                msg_id  = rc_msg.get("_id", "")
                text    = rc_msg.get("msg", "").strip()
            except (KeyError, IndexError, TypeError):
                return

            # Skip messages we sent ourselves (by ID, not username —
            # so two nodes using the same account still work correctly)
            if msg_id and msg_id in self._sent_ids:
                self._sent_ids.discard(msg_id)  # free memory once seen
                return
            if not (text.startswith("HELLO:") or text.startswith("PKT:")):
                return

            log.debug("RX from %s: %s…", sender, text[:60])
            _tunnel.receive(text)

    def _on_ws_error(self, ws, error) -> None:
        log.warning("WS error: %s", error)

    def _on_ws_close(self, ws, code, reason) -> None:
        log.warning("WS closed (code=%s reason=%s)", code, reason)
        self._connected.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_transport: RocketChatTransport | None = None


def start() -> None:
    """
    Connect to Rocket.Chat and wire tunnel.send.
    Call this before tunnel.tunnel.start().
    """
    global _transport
    _transport = RocketChatTransport()
    _transport.start()


# ---------------------------------------------------------------------------
# Standalone connection test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    print("Rocket.Chat transport connection test")
    print(f"  Server  : {RC_URL or '(RC_URL not set)'}")
    print(f"  Auth    : {'token (RC_AUTH_TOKEN)' if _USE_TOKEN_AUTH else 'password (RC_USERNAME/RC_PASSWORD)'}")
    print(f"  User    : {RC_USERNAME or RC_USER_ID or '(not set)'}")
    print(f"  Channel : #{RC_CHANNEL}")
    print()

    # Stub out tunnel.send so we don't need a real tunnel running
    _tunnel.send = lambda msg: None

    start()
    print("Connected. Listening for tunnel messages (Ctrl-C to stop)…\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDone.")
