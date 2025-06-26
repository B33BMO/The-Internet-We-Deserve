import os
import base64

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def split_file(filepath, num_shards, min_needed, key):
    with open(filepath, "rb") as f:
        data = f.read()
    chunk_size = len(data) // num_shards + (1 if len(data) % num_shards else 0)
    shards = []
    for i in range(num_shards):
        chunk = data[i*chunk_size : (i+1)*chunk_size]
        enc_chunk = xor_encrypt(chunk, key)
        shards.append(enc_chunk)
    return shards

def recover_file(shards, out_path, key):
    dec_data = b''.join([xor_encrypt(shard, key) for shard in shards])
    with open(out_path, "wb") as f:
        f.write(dec_data)
    print(f"🗃️  File recovered to {out_path}")

class ShardManager:
    def __init__(self, node):
        self.node = node
        self.shards_received = {}

    async def handle_shard(self, data, addr):
        file_id = data.get("file_id")
        index = data.get("shard_index")
        shard = base64.b64decode(data.get("shard"))
        if file_id not in self.shards_received:
            self.shards_received[file_id] = {}
        self.shards_received[file_id][index] = shard
        print(f"Received shard {index} for file {file_id} from {addr[0]}")
        total = data.get("total_shards")
        min_needed = data.get("min_needed", total)
        if len(self.shards_received[file_id]) >= min_needed:
            out_path = f"recovered_{file_id}"
            recover_file([self.shards_received[file_id][i] for i in sorted(self.shards_received[file_id])], out_path, self.node.keypair['public'].public_bytes(
                encoding=self.node.keypair['public'].__class__.public_bytes_encoding,
                format=self.node.keypair['public'].__class__.public_bytes_format
            ))
