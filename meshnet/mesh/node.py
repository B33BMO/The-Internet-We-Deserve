import asyncio
from mesh.crypto import load_or_create_keypair, sign_message, verify_signature, public_key_from_b64
from mesh.sharding import split_file, ShardManager
import os
import base64
from cryptography.hazmat.primitives import serialization

class MeshNode:
    def __init__(self, username, keypair=None, transports=None, shard_manager=None, dns=None):
        self.username = username
        self.keypair = keypair if keypair else load_or_create_keypair(username)
        self.transports = transports if transports else []
        self.shard_manager = shard_manager if shard_manager else ShardManager(self)
        self.dns = dns
        self.peers = {}  # peer_id/ip: pubkey_b64
        self.plugins = []
        self.running = True

    async def announce_self(self):
        for t in self.transports:
            await t.announce(self.username)
        print(f"Announced self as {self.username}")

    async def run(self):
        print("🟢 Node event loop running...")
        tasks = [asyncio.create_task(t.listen()) for t in self.transports]
        while self.running:
            await asyncio.sleep(0.5)
        for t in tasks:
            t.cancel()
        print("Node event loop stopped.")

    async def handle_incoming(self, data, addr, transport):
        msg_type = data.get("type")
        if msg_type == "peer_announce":
            peer_id = data.get("user", addr[0])
            pubkey_b64 = data.get("pubkey")
            sig = data.get("sig")
            payload = (peer_id + pubkey_b64).encode()
            try:
                self.peers[peer_id] = {
    "ip": addr[0],
    "pubkey_b64": pubkey_b64
}

                if sig and verify_signature(pubkey, payload, sig):
                    self.peers[addr[0]] = pubkey_b64  # <---- store by IP!
                    print(f"👋 VERIFIED peer: {peer_id} [{addr[0]}]")
                else:
                    print(f"⚠️ Unverified peer announce: {peer_id} [{addr[0]}]")
            except Exception as e:
                print(f"❌ Peer pubkey error: {e}")
        elif msg_type == "message":
            sender = data.get("user", addr[0])
            pubkey_b64 = data.get("pubkey")
            sig = data.get("sig")
            text = data.get("data")
            if pubkey_b64 and sig:
                try:
                    pubkey = public_key_from_b64(pubkey_b64)
                    if verify_signature(pubkey, text.encode(), sig):
                        print(f"💬 [{sender}] {text} (verified)")
                    else:
                        print(f"💬 [{sender}] {text} (FAILED signature)")
                except Exception as e:
                    print(f"💬 [{sender}] {text} (pubkey error: {e})")
            else:
                print(f"💬 [{sender}] {text} (NO signature)")
        elif msg_type == "shard":
            if self.shard_manager:
                await self.shard_manager.handle_shard(data, addr)
        elif msg_type == "dns":
            if self.dns:
                await self.dns.handle_dns(data, addr)
        else:
            print(f"❓ Unknown message type: {msg_type}")

    async def send_message(self, text):
        for t in self.transports:
            await t.send_message(text, list(self.peers.keys()))

    async def repl(self):
        print("Enter commands: /msg <text>, /peers, /announce, /shard <file>, /exit")
        loop = asyncio.get_event_loop()
        while self.running:
            cmd = await loop.run_in_executor(None, input, "> ")
            if cmd.startswith("/msg "):
                await self.send_message(cmd[5:])
            elif cmd == "/peers":
                print("Known peers:", self.peers)
            elif cmd == "/announce":
                await self.announce_self()
            elif cmd.startswith("/shard "):
                path = cmd.split(" ", 1)[1]
                if not os.path.isfile(path):
                    print("File does not exist.")
                    continue
                print(f"Sharding and sending file: {path}")
                shards = split_file(path, num_shards=5, min_needed=3, key=self.keypair['public'].public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ))
                for i, shard in enumerate(shards):
                    for t in self.transports:
                        await t.send_shard({
                            "type": "shard",
                            "file_id": os.path.basename(path),
                            "shard_index": i,
                            "total_shards": len(shards),
                            "min_needed": 3,
                            "shard": base64.b64encode(shard).decode(),
                        }, list(self.peers.keys()))
            elif cmd == "/exit":
                self.running = False
            else:
                print("Unknown command. Try /msg, /peers, /announce, /shard <file>, /exit")
