#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define IPv4_TYPE 0x0800
#define ARP_TYPE 0x0806
#define MAX_LEN 1e5

typedef struct node {
	struct route_table_entry *entry;
	struct node *children[2];
} node_t;

typedef struct cell {
	char packet[MAX_PACKET_LEN];
	struct cell *next;
} queue_t;

/* arp_table path and pointer */
char *arp_table_path = "./arp_table.txt";
int route_table_len, arp_table_len;

/* only for debugging purposes */
void print_ip_address(uint32_t ip_addr) {
    uint8_t *ip_bytes = (uint8_t *) &ip_addr;
    printf("%d.%d.%d.%d\n", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}

void print_mac_address(uint8_t *mac_addr) {
	printf("%x:%x:%x:%x:%x:%x    ", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

node_t *alloc_node(void) {
    node_t *new_node = malloc(sizeof(node_t));
    if (new_node) {
        new_node->entry = NULL;
        new_node->children[0] = NULL;
        new_node->children[1] = NULL;
    }
    return new_node;
}

void insert_node(node_t *root, struct route_table_entry *entry, uint32_t mask, uint32_t prefix) {
    node_t *current = root;
    // iterating through the bits of the mask, from the most significant bit to the least
    for (int bit_index = 31; bit_index >= 0; bit_index--) {
        // if I reach a 0 in the mask, it means that the prefix is over
        if (!(mask & (1U << bit_index)))
            break;
        // extracting the bit value from the prefix
        int bit_val = (prefix >> bit_index) & 1;

        if (current->children[bit_val] == NULL) {
            current->children[bit_val] = alloc_node();
        }
        current = current->children[bit_val];
    }
    // current node is the leaf node where we store the entry
    current->entry = entry;
}

struct route_table_entry *search_ip(node_t *root, uint32_t ip_dest) {
    struct route_table_entry *best_match = NULL;
    node_t *current = root;
    // iterating through the bits of the destination IP address
    for (int bit_index = 31; bit_index >= 0; bit_index--) {
		// bit_val is the value of the bit at index bit_index
        int bit_val = (ip_dest >> bit_index) & 1;
        if (current->children[bit_val] == NULL)
            break;
        current = current->children[bit_val];
        // if the current node has an entry, it means we have a match
        if (current->entry)
            best_match = current->entry;
    }
    return best_match;
}

node_t *init_trie(struct route_table_entry *route_table) {
    node_t *trie = (node_t *)calloc(1, sizeof(node_t));
    // iterating through the route table and inserting each entry in the trie
    for (int i = 0; i < route_table_len; i++) {
        // need htonl for the mask and prefix to convert them in big endian
        uint32_t conv_mask = htonl(route_table[i].mask);
        uint32_t conv_prefix = htonl(route_table[i].prefix);
        insert_node(trie, &route_table[i], conv_mask, conv_prefix);
    }
    return trie;
}

queue_t *init_queue(void) {
    queue_t *queue = (queue_t *)calloc(1, sizeof(queue_t));
    queue->next = NULL;
    return queue;
}

queue_t *add_to_queue(queue_t *queue, char *packet, size_t len) {
    queue_t *new_cell = (queue_t *)calloc(1, sizeof(queue_t));
    memcpy(new_cell->packet, packet, len);
    new_cell->next = NULL;
    
    queue_t *cell;
    for (cell = queue; cell->next != NULL; cell = cell->next);
    cell->next = new_cell;
    
    return new_cell;
}

queue_t *extract_from_queue(queue_t *queue) {
    if (queue == NULL || queue->next == NULL)
        return NULL;

    queue_t *first = queue->next;
    queue->next = first->next;
    
    return first;
}

int init_tables(char *argv[], struct route_table_entry *route_table, struct arp_table_entry *arp_table) {
	route_table_len = read_rtable(argv[1], route_table);
	if (route_table_len < 0) {
		printf("nu am putut citi tabela de rutare\n");
		return -1;
	}

	arp_table_len = parse_arp_table(arp_table_path, arp_table);
	if (arp_table_len < 0) {
		printf("nu am putut citi tabela de intrari arp\n");
		return -1;
	}

	return 0;
}

int init_route_table(char *argv[], struct route_table_entry *route_table) {
	route_table_len = read_rtable(argv[1], route_table);
	if (route_table_len < 0) {
		printf("nu am putut citi tabela de rutare\n");
		return -1;
	}
	return 0;
}

struct arp_table_entry *get_mac_entry(uint32_t ip_dest, struct arp_table_entry *arp_table) {
	for (int i = 0; i < arp_table_len; i++) {
		printf("ip dest e %u, ip table e %u\n", ip_dest, arp_table[i].ip);
		if (arp_table[i].ip == ip_dest) {
			printf("am gasit mac-ul\n");
			return &arp_table[i];
		}
	}
	return NULL;
}

char *generate_icmp_message(struct ether_hdr *orig_eth_hdr,
							struct ip_hdr *orig_ip_hdr,
							int type, int code,
							int *msg_len)
{
	int ip_header_len = orig_ip_hdr->ihl * 4;
	int payload_size = ip_header_len + 8; 
	int total_size = sizeof(struct icmp_hdr) + payload_size;

	char *icmp_packet = malloc(total_size);
	if (icmp_packet == NULL) {
		printf("eroare la alocarea bufferului pentru icmp\n");
		return NULL;
	}
	memset(icmp_packet, 0, total_size);

	struct icmp_hdr *icmp = (struct icmp_hdr *)icmp_packet;
	icmp->mtype = type;
	icmp->mcode = code;

	// copying the orginal ip header
	memcpy(icmp_packet + sizeof(struct icmp_hdr), orig_ip_hdr, ip_header_len);
	// copying the first 8 bytes from the original payload
	memcpy(icmp_packet + sizeof(struct icmp_hdr) + ip_header_len, (char *)orig_ip_hdr + ip_header_len, 8);

	icmp->check = 0;
	int cksum = checksum((uint16_t *)icmp_packet, total_size);
	icmp->check = htons(cksum);

	*msg_len = total_size;
	return icmp_packet;
}

int send_icmp_packet(struct ether_hdr *orig_eth_hdr,
					 struct ip_hdr *orig_ip_hdr,
					 char *icmp_msg, int icmp_msg_len,
					 struct route_table_entry *route_table, int route_table_len,
					 size_t interface)
{
	// new destination is actually source address
	uint32_t dest_ip = orig_ip_hdr->source_addr;

	// buffer for new header: [Ethernet header] + [IP header] + [ICMP message]
	int ip_header_len = sizeof(struct ip_hdr);
	int total_packet_len = sizeof(struct ether_hdr) + ip_header_len + icmp_msg_len;
	// int total_packet_len = MAX_PACKET_LEN;
	char *packet = (char *)malloc(total_packet_len);

	memset(packet, 0, total_packet_len);

	// "building" the eth header
	struct ether_hdr *eth = (struct ether_hdr *)packet;

	memcpy(eth->ethr_dhost, orig_eth_hdr->ethr_shost, 6);
	memcpy(eth->ethr_shost, orig_eth_hdr->ethr_dhost, 6);

	// get_interface_mac(interface, eth->ethr_shost);
	eth->ethr_type = htons(IPv4_TYPE);

	struct ip_hdr *ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	ip->ver = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(ip_header_len + icmp_msg_len);
	ip->id = 0;
	ip->frag = 0;
	ip->ttl = 64; 															// standard TTL ?
	ip->proto = 1; 															// 1 = ICMP
	ip->source_addr = inet_addr(get_interface_ip(interface));		// source ip: ip address of the exit interface
	ip->dest_addr = dest_ip;												// dest address = source address of the sender (dest_ip)
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, ip_header_len));

	// copying the icmp message in the packet
	memcpy(packet + sizeof(struct ether_hdr) + ip_header_len, icmp_msg, icmp_msg_len);

	// sending the packet on the exit interface
	int res = send_to_link(total_packet_len, packet, interface);
	printf("apeleaza functia, ar treb sa trimita pachetu, res e %d\n", res);
	if (res < 0) {
		printf("s a pierdut pe drum pachetul icmp\n");
		free(packet);
		return -1;
	}
	free(packet);
	return 0;
}

struct arp_hdr *generate_arp_request(struct ether_hdr *orig_eth_hdr,
						 			 struct ip_hdr *orig_ip_hdr,
									 uint32_t interface_ip,
									 struct route_table_entry *closest_router,
						 			 uint16_t opcode)
{
	struct arp_hdr *arp_hdr = (struct arp_hdr *)calloc(1, sizeof(struct arp_hdr));
	if (arp_hdr == NULL) {
		printf("eroare la alocarea bufferului pentru arp\n");
		return NULL;
	}

	uint8_t broadcast_mac[6];
	for (int i = 0; i < 6; i++) {
		broadcast_mac[i] = 0xff;
	}

	arp_hdr->hw_type = htons(opcode);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(opcode);

	char *interface_ip_str = get_interface_ip(closest_router->interface);
	uint8_t interface_ip_bytes[4];
	inet_pton(AF_INET, interface_ip_str, interface_ip_bytes);

	get_interface_mac(closest_router->interface, arp_hdr->shwa);
	arp_hdr->sprotoa = (*(uint32_t*)interface_ip_bytes);
	memcpy(arp_hdr->thwa, broadcast_mac, 6);
	arp_hdr->tprotoa = closest_router->next_hop; // orig_ip_hdr->dest_addr;

	return arp_hdr;
}

int sent_arp_packet(struct ether_hdr *orig_eth_hdr,
					 struct ip_hdr *orig_ip_hdr,
					 struct arp_hdr *arp_hdr,
					 size_t interface)
{
	// buffer for new header: [Ethernet header] + [ARP header]
	int total_packet_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	char *packet = (char *)malloc(total_packet_len);

	memset(packet, 0, total_packet_len);

	// "building" the eth header
	struct ether_hdr *eth = (struct ether_hdr *)packet;
	eth->ethr_type = htons(ARP_TYPE);

	uint8_t interface_mac[6];
	uint8_t null_mac[6];
	for (int i = 0; i < 6; i++) {
		null_mac[i] = 0xff;
	}

	get_interface_mac(interface, interface_mac);
	memcpy(eth->ethr_shost, interface_mac, 6);
	memcpy(eth->ethr_dhost, null_mac, 6);

	struct arp_hdr *arp = (struct arp_hdr *)(packet + sizeof(struct ether_hdr));
	memcpy(arp, arp_hdr, sizeof(struct arp_hdr));

	// sending the packet on the exit interface
	int res = send_to_link(total_packet_len, packet, interface);
	if (res < 0) {
		printf("s a pierdut pe drum pachetul arp\n");
		free(packet);
		return -1;
	}
	free(packet);
	return 0;
}

void parse_arp_reply(char *buf, struct arp_table_entry *arp_table) {
	// struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	printf("se ntampla parsare sper? \n");

	uint32_t ip_addr = arp_hdr->sprotoa;
	memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
	arp_table[arp_table_len].ip = ip_addr;
	arp_table_len++;
}

void handle_icmp_cases(struct route_table_entry *closest_router, 
						struct ether_hdr *eth_hdr,
						struct ip_hdr *ip_hdr,
						struct route_table_entry *route_table, int route_table_len,
						size_t interface, char *interface_ip)
{
	if (closest_router == NULL) {
		/* first case for icmp */
		printf("nu e cale in tabela de rutare\n");
		int icmp_msg_len;
		char *icmp_msg = generate_icmp_message(eth_hdr, ip_hdr, 3, 0, &icmp_msg_len);
		if (icmp_msg != NULL) {
			send_icmp_packet(eth_hdr, ip_hdr, icmp_msg, icmp_msg_len,
							route_table, route_table_len, interface);
			free(icmp_msg);
		}
	}
	
	if (ip_hdr->ttl <= 1) {
		/* second case for icmp */
		printf("TTL ul a expirat\n");
		int icmp_msg_len;
		char *icmp_msg = generate_icmp_message(eth_hdr, ip_hdr, 11, 0, &icmp_msg_len);
		if (icmp_msg != NULL) {
			send_icmp_packet(eth_hdr, ip_hdr, icmp_msg, icmp_msg_len,
							 route_table, route_table_len, interface);
			free(icmp_msg);
		}
	}

	if (ip_hdr->proto == 1 && ip_hdr->dest_addr == *(uint32_t *)interface_ip) {
		int icmp_msg_len;
		char *icmp_msg = generate_icmp_message(eth_hdr, ip_hdr, 0, 0, &icmp_msg_len);
		if (icmp_msg != NULL) {
			send_icmp_packet(eth_hdr, ip_hdr, icmp_msg, icmp_msg_len,
							route_table, route_table_len, interface);
			free(icmp_msg);
		}
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *route_table = (struct route_table_entry *)calloc(MAX_LEN, sizeof(struct route_table_entry));
	struct arp_table_entry *arp_table = (struct arp_table_entry *)calloc(MAX_LEN, sizeof(struct arp_table_entry));

	// init_tables(argv, route_table, arp_table);
	init_route_table(argv, route_table);
	node_t *trie = init_trie(route_table);
	queue_t *queue = init_queue();

	// Do not modify this line
	init(argv + 2, argc - 2);

	while (1) {
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("am primit un pachet\n");
		uint8_t interface_ip1[4];

		inet_pton(AF_INET, get_interface_ip(interface), interface_ip1);
		uint32_t interface_ip2 = *(uint32_t *)interface_ip1;

    	// TODO: Implement the router forwarding logic

    	/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */
	
		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
		if (ntohs(eth_hdr->ethr_type) == ARP_TYPE) {
			// int offset_to_opcode = sizeof(struct ether_hdr) + 6;
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			uint16_t arp_request_op = arp_hdr->opcode;
			printf("am primit pachet arp, arp  op e %hu\n", ntohs(arp_request_op));

			if (ntohs(eth_hdr->ethr_type) == ARP_TYPE && ntohs(arp_request_op) == 2) {
				// struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
				printf("se primeste un pachet arp reply\n");
				parse_arp_reply(buf, arp_table);

				queue_t *cell = extract_from_queue(queue);
				printf("se extrage pachet din coada\n");
				if (cell == NULL) {
					printf("rip1\n");
					continue;
				}

				memcpy(buf, cell->packet, MAX_PACKET_LEN);

				struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)buf + sizeof(struct ether_hdr));
				struct route_table_entry *closest_router = search_ip(trie, htonl(ip_hdr->dest_addr));
		
				ip_hdr->ttl--;
				ip_hdr->checksum = 0;
				ip_hdr->checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

				// print_ip_address(closest_router->next_hop);
				struct arp_table_entry *nexthop_mac = get_mac_entry(closest_router->next_hop, arp_table);

				if (nexthop_mac == NULL) {
					printf("nu am gasit mac-ul destinatiei \n");
					add_to_queue(queue, cell->packet, len);
					continue;
				}
		
				memcpy(eth_hdr->ethr_dhost, nexthop_mac->mac, sizeof(eth_hdr->ethr_dhost));
				get_interface_mac(closest_router->interface, eth_hdr->ethr_shost);
		
				// sending the packet
				// printf("Packet transmis pe %d!\n", closest_router->interface);
				// print_ip_address(ip_hdr->source_addr);
				// print_ip_address(ip_hdr->dest_addr);
				// print_mac_address(eth_hdr->ethr_shost);
				// print_mac_address(eth_hdr->ethr_dhost);
		
				size_t new_len = ntohs(ip_hdr->tot_len) + sizeof(struct ether_hdr);
				printf("se trim pe %d len = %lu\n", closest_router->interface, new_len);
				int res = send_to_link(new_len, buf, closest_router->interface);
				(void)res;

				continue;
			} else if (ntohs(eth_hdr->ethr_type) == ARP_TYPE && ntohs(arp_request_op) == 1) {
				printf("se primeste un pachet arp request\n");

				uint8_t mac[6];
				get_interface_mac(interface, mac);

				memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
				memcpy(arp_hdr->thwa, eth_hdr->ethr_shost, 6);
				memcpy(eth_hdr->ethr_shost, mac, 6);
				memcpy(arp_hdr->shwa, mac, 6);

				uint32_t aux_ip = arp_hdr->sprotoa;
				arp_hdr->sprotoa = arp_hdr->tprotoa;
				arp_hdr->tprotoa = aux_ip;
				arp_hdr->opcode = ntohs(2);

				// printf("Il pasez pe %d\n", next_hop->interface);
				send_to_link(len, buf, interface);
				continue;
			}
		} else {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));

			uint16_t sum_int = ip_hdr->checksum;
			ip_hdr->checksum = 0;
	
			if (sum_int != htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)))) {
				printf("ai gresit pachetu' baiatu meu\n");
				memset(buf, 0, sizeof(buf));
				continue;
			}

			// print_ip_address(ip_hdr->dest_addr);
			// struct route_table_entry *closest_router = get_best_route(ip_hdr->dest_addr, route_table, route_table_len);
			struct route_table_entry *closest_router = search_ip(trie, htonl(ip_hdr->dest_addr));
	
			if (closest_router == NULL || ip_hdr->ttl <= 1 || (ip_hdr->proto == 1 && ip_hdr->dest_addr == *(uint32_t *)interface_ip1)) {
				handle_icmp_cases(closest_router, eth_hdr, ip_hdr, route_table, route_table_len, interface, (char *)interface_ip1);
				continue;
			}

			struct arp_table_entry *arp_entry = get_mac_entry(closest_router->next_hop, arp_table);

			// handling arp request case
			if (arp_entry == NULL) {
				add_to_queue(queue, buf, len);

				uint16_t opcode = 1;
				struct arp_hdr *arp_hdr = generate_arp_request(eth_hdr, ip_hdr, interface, closest_router, opcode);
				printf("se trimite pachetul arp\n");
				int res = sent_arp_packet(eth_hdr, ip_hdr, arp_hdr, closest_router->interface);
				if (res < 0) {
					printf("s a pierdut pe drum pachetul arp\n");
					free(arp_hdr);
					continue;
				}
				continue;
			} else {		
				ip_hdr->ttl--;
				ip_hdr->checksum = 0;
				ip_hdr->checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
				
				// print_ip_address(closest_router->next_hop);
				struct arp_table_entry *nexthop_mac = get_mac_entry(closest_router->next_hop, arp_table);

				memcpy(eth_hdr->ethr_dhost, nexthop_mac->mac, sizeof(eth_hdr->ethr_dhost));
				get_interface_mac(closest_router->interface, eth_hdr->ethr_shost);
				
				int res = send_to_link(len, buf, closest_router->interface);
				(void)res;
			}
		}
	}
}

