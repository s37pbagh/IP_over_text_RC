"""
main.py — entry point wiring Rocket.Chat transport into the tunnel.
"""
import logging
import time

import rocketchat_transport
import tunnel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def main() -> None:
    print()
    print("Starting Rocket.Chat ↔ TUN tunnel…")
    print()

    # 1. Connect to Rocket.Chat and wire tunnel.send → RC channel
    rocketchat_transport.start()

    # 2. Open TUN interface, send HELLO, begin tunnelling
    tunnel.tunnel.start()

    print()
    print("Tunnel is up. Press Ctrl-C to stop.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down…")
        tunnel.tunnel.stop()

if __name__ == "__main__":
    main()
