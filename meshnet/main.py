import asyncio
import sys
from mesh.node import MeshNode
from mesh.transport import LANTransport

async def main():
    # Get username from CLI or prompt
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Username: ").strip() or "anonymous"

    print(f"Launching MeshNode as '{username}'")

    node = MeshNode(username)
    lan = LANTransport(node)
    node.transports = [lan]

    # Announce self on the LAN
    await node.announce_self()

    # Start transport listener and interactive REPL in parallel
    await asyncio.gather(
        node.run(),
        node.repl()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting meshnet. Later, nerd 🤙")
