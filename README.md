# Router — LPM, ARP, IPv4 Forwarding & ICMP

A fully functional software router implemented in C, capable of forwarding IPv4 packets, resolving MAC addresses via ARP, and handling ICMP messages. Built from scratch as part of a networks course assignment, this project covers the entire packet-forwarding pipeline — from receiving a raw frame to deciding where it goes next and making sure it gets there correctly.

---

## What it does

At its core, this router does what any real router does: it receives packets, figures out where they need to go, resolves the hardware addresses needed to get them there, and handles error cases gracefully. The full implementation covers:

- **Efficient longest-prefix matching** using a binary trie
- **ARP request/reply handling** for MAC address resolution
- **IPv4 packet forwarding** with checksum validation
- **ICMP** for destination unreachable, TTL exceeded, and echo reply

---

## Technical breakdown

### Longest Prefix Match — Trie

The naive approach to LPM (iterating through the entire routing table for every packet) doesn't scale. Instead, I built a **binary trie** where each node branches on a single bit of the IP address, from most significant to least significant. Each leaf stores the matching routing table entry.

- `alloc_node` — initializes a trie node  
- `insert_node` — inserts a routing entry, converting from little-endian to big-endian bit order during traversal  
- `init_trie` — builds the full trie from the routing table file at startup  
- `search_ip` — walks the trie bit by bit and returns the best matching entry in O(32) time, regardless of table size  

This gives O(1) worst-case lookup relative to table size, which is a meaningful improvement over a linear scan when routing tables get large.

### ARP

ARP is what lets the router figure out the MAC address of the next hop before it can actually send a packet. The logic handles two cases:

**Receiving an ARP reply:** The router parses the reply, updates its ARP table, then pulls packets from the queue that were waiting on this MAC address and forwards them with the now-resolved destination MAC.

**Receiving an ARP request:** The router reverses the source/destination fields in both the Ethernet and ARP headers and sends a reply back out the same interface it came in on.

**Sending ARP requests:** When the router needs to forward a packet but doesn't have the next hop's MAC address yet, it queues the packet and sends out an ARP request using `generate_arp_request` and `send_arp_packet`.

### IPv4 Forwarding

When the router receives an IPv4 packet, it:

1. Validates the checksum — if it doesn't match, the packet is dropped
2. Looks up the best matching route via the trie
3. Looks up the next hop's MAC address in the ARP table
4. If the MAC isn't cached yet, queues the packet and fires an ARP request
5. If the MAC is available, updates the Ethernet header and forwards the packet

### ICMP

The `handle_icmp_cases` function covers the three required scenarios:

- **Destination Unreachable** — sent when no matching route is found
- **Time Exceeded** — sent when TTL drops to 1 or below (the router won't decrement and forward a zero-TTL packet)
- **Echo Reply** — sent when the router itself is the destination of a ping

Packet construction is split between `generate_icmp_message` (builds the ICMP payload as a buffer) and `send_icmp_packet` (wraps it in IP and Ethernet headers and sends it out).

---

## Skills demonstrated

This project involves working close to the metal — manually constructing and parsing packet headers, managing memory carefully in C, and reasoning about the ordering and timing of network events (like what happens when you receive an ARP reply for a packet that's already been queued for a while).

Relevant to roles that require a solid understanding of:

- **Operating system fundamentals** — memory management, pointers, and data structures in C
- **Network protocols** — deep, hands-on familiarity with Ethernet, IPv4, ARP, and ICMP at the byte level
- **Client-server architecture and packet flow** — understanding how data actually moves across a network
- **Linux CLI** — the project runs and is tested in a Linux environment using network namespaces and virtual interfaces
- **Low-level debugging** — tracking down off-by-one errors in bit manipulation, endianness bugs, and race conditions in packet queuing

---

## Project structure

```
router.c          # Main router logic — forwarding, ARP, ICMP
include/          # Header files for packet structures
rtable.txt        # Routing table used to build the trie
README.md         # This file
```

---

## Running it

The router is designed to run in a Mininet-based network topology. Once compiled, it reads the routing table from `rtable.txt`, builds the trie, and starts listening on all interfaces.

```bash
make
./router rtable.txt
```

---

## Notes

The ARP queue logic handles the edge case where a reply arrives but still doesn't resolve a cached packet's next hop — in that case, the packet goes back on the queue. In practice this shouldn't happen in a well-behaved topology, but it's handled defensively.