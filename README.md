# RWP
Retro Web Protocol

RRKDHT (Rotating Rendezvous Kademlia DHT) Web
This project is built around RRKDHT (Rotating Rendezvous Kademlia DHT) for the Web.
It’s divided into three main parts:

- Core
- Server
- Client

All three parts use the Core, since each one acts as a node — meaning the server and client are both considered nodes as well.

Currently:
The Server and Client are ready (but still missing the Core integration).
The Core is still under development.

⚠️ Early Release Notice:
This is an early release version!

What’s Left:
- The only thing remaining in the Core is implementing the rendezvous_key search/find feature. (DONE)
- Integrate the real server (not tserver.py), with the core (RRKDHT.py).

Interrupted integration, Because Ive made a mistake. (I've fixed the mistake and proof-tested it 3 times) but I'm still working on one last update!

Note:
It may take a while to be ready for real use (production), Because i have studies and AI is not that good in helping.
(Also i don't get paid for this shit)
