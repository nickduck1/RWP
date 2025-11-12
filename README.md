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

Interrupted integration, Because Ive made a big mistake. (Easy fix, But working on it. May take time!)
Broblem fixed, But the new implementation still has some bugs. So I'm still proof-testing it!!

Note:
It may take a while to be ready for real use (production), Because i have studies and AI is not that good in helping.
(Also i don't get paid for this shit)
