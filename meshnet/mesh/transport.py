import asyncio
import socket
import json
import base64
from cryptography.hazmat.primitives import serialization
from mesh.crypto import sign_message

class LANTransport:
    name = "LAN"

    def __init__(self, node, port=15001):
        self.node = node
        self.port = port
        self.running = True

    async def announce(self, username):
        pubkey = self.node.keypair['public']
        pubkey_bytes = pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pubkey_b64 = base64.b64encode(pubkey_bytes).decode()
        payload = (username + pubkey_b64).encode()
        sig = sign_message(self.node.keypair['private'], payload)
        msg = json.dumps({
            "type": "peer_announce",
            "user": username,
            "pubkey": pubkey_b64,
            "sig": sig
        }).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(msg, ('<broadcast>', self.port))
        sock.close()
        print("🔊 Broadcasted announce on LAN")

    async def send_message(self, text, peers):
        pubkey = self.node.keypair['public']
        pubkey_bytes = pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pubkey_b64 = base64.b64encode(pubkey_bytes).decode()
        sig = sign_message(self.node.keypair['private'], text.encode())
        msg = json.dumps({
            "type": "message",
            "user": self.node.username,
            "pubkey": pubkey_b64,
            "sig": sig,
            "data": text
        }).encode()
        for peer in peers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(msg, (peer, self.port))
            except Exception as e:
                print(f"LAN send error: {e}")
            finally:
                sock.close()
        print(f"📤 Sent signed message to {len(peers)} peers")

    async def send_shard(self, shard_info, peers):
        msg = json.dumps(shard_info).encode()
        for peer in peers:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(msg, (peer, self.port))
            except Exception as e:
                print(f"LAN send error (shard): {e}")
            finally:
                sock.close()
        print(f"📦 Sent shard to {len(peers)} peers")

    async def listen(self):
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.port))
        sock.setblocking(False)
        print(f"🛰️  LANTransport listening on UDP {self.port}")

        own_ip = self.get_own_ip()
        print(f"LANTransport thinks our IP is: {own_ip}")

        while self.running:
            try:
                data, addr = await loop.run_in_executor(None, sock.recvfrom, 65536)
                print(f"LAN RX: Got data from {addr[0]}:{addr[1]}")
                msg = json.loads(data)
                # --- comment this next line for now ---
                # if addr[0] != own_ip:
                await self.node.handle_incoming(msg, addr, self)
            except Exception as e:
                await asyncio.sleep(0.1)


    def get_own_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
