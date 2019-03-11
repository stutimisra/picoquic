// XIA Headers
#include "xiaapi.hpp"

// QUIC Headers
extern "C" {
#include "util.h"    // DBG_PRINTF
};

// C++ Headers
#include <iostream>
#include <string>
#include <memory>    // unique_ptr

// C Headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>

// Let's hard code the router's address for now
#define ROUTER_ADDR "172.16.148.166"
#define ROUTER_PORT 8769

// Also, hard coding our address, for now
#define OUR_ADDR "AD:69a4e068880cd40549405dfda6e794b0c7fdf191 HID:59f1978899b8a8c866d1b7992f66f91e1422efc9"

/*
void xiaapitest()
{
	std::cout << "Hello XIA Test" << std::endl;
}
*/


// Open a server socket
// Associate it to given AID
//
// Returns socket descriptor and our local address, on Success
// Returns -1, on Failure
int picoquic_xia_open_server_socket(char* aid, GraphPtr& my_addr)
{
	std::cout << "Opening a server socket with XIA headers" << std::endl;
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd == -1) {
		return -1;
	}
	std::cout << "Underlying IP socket created" << std::endl;

	// Find the default local address
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;

	if(getifaddrs(&ifap)) {
		std::cout << "ERROR getting local interface addresses" << std::endl;
		return -1;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family==AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			if(strncmp(ifa->ifa_name, "lo", 2) == 0) {
				sa = NULL;
				continue;
			}
			addr = inet_ntoa(sa->sin_addr);
			printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
			break;
		}
	}
	if(ifa == NULL) {
		std::cout << "ERROR couldn't find a local address" << std::endl;
		freeifaddrs(ifap);
		return -1;
	}
	// 'sa' now points to a valid local address

	// Bind to a random port
	printf("Binding to %s:%d\n", inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
	if(bind(sockfd, (struct sockaddr*) sa, sizeof(sockaddr_in))) {
		std::cout << "Failed binding to a port" << std::endl;
		freeifaddrs(ifap);
		return -1;
	}
	freeifaddrs(ifap);

	// Find out the port that we bound to
	struct sockaddr_in bound_addr;
	socklen_t bound_addrlen = sizeof(struct sockaddr_in);
	if(getsockname(sockfd, (struct sockaddr*)&bound_addr, &bound_addrlen)) {
		std::cout << "ERROR getting address we bound to" << std::endl;
		return -1;
	}
	printf("Bound to %s:%d\n", inet_ntoa(bound_addr.sin_addr),
			ntohs(bound_addr.sin_port));

	// Our XIA address, to be used for sending packets out
	std::string aidstr(aid);
	std::string xiaaddrstr = std::string("RE ") + OUR_ADDR +  " " + aidstr;
	std::cout << "Our address:" << xiaaddrstr << std::endl;
	my_addr.reset(new Graph(xiaaddrstr));

	// Tell the router to create a route to us
	struct sockaddr_in router_addr;
	if(picoquic_xia_router_addr(&router_addr)) {
		std::cout << "Error getting router address" << std::endl;
		freeifaddrs(ifap);
		return -1;
	}
	printf("Router addr found: %s\n", inet_ntoa(router_addr.sin_addr));
	char raddr_str[1024];
	if(inet_ntop(AF_INET, &(router_addr.sin_addr),
				raddr_str, sizeof(raddr_str)) == NULL) {
		std::cout << "Error converting router addr to string" << std::endl;
		freeifaddrs(ifap);
		return -1;
	}
	std::cout << "Found router address " << std::string(raddr_str) << std::endl;

	uint8_t buffer[1024];
	size_t buffer_offset = 0;
	// Start with 0xc0da (tells router this is a registration packet
	buffer[buffer_offset++] = 0xc0;
	buffer[buffer_offset++] = 0xda;
	// Now add AID size and the AID as a string itself
	buffer[buffer_offset++] = (uint8_t)aidstr.size();
	std::cout << "AID size: " << aidstr.size() << std::endl;
	memcpy(&buffer[buffer_offset], aidstr.data(), aidstr.size());
	buffer_offset += aidstr.size();
	// Add our address and port here
	buffer[buffer_offset++] = sizeof(struct sockaddr_in);
	printf("Our address: %s\n", inet_ntoa(bound_addr.sin_addr));
	printf("Our port in network byte order %d\n", bound_addr.sin_port);
	printf("Our port: %d\n", ntohs(bound_addr.sin_port));
	memcpy(&buffer[buffer_offset], &bound_addr, sizeof(struct sockaddr_in));
	buffer_offset += sizeof(struct sockaddr_in);

	// Send the registration packet to the router
	int retval = sendto(sockfd, buffer, buffer_offset, 0,
			(struct sockaddr*)&router_addr, sizeof(router_addr));
	if(retval != buffer_offset) {
		std::cout << "ERROR sending registration packet" << std::endl;
		return -1;
	}

	struct sockaddr_storage myaddr;
	socklen_t myaddrlen = sizeof(struct sockaddr_storage);
	if(getsockname(sockfd, (struct sockaddr*)&myaddr, &myaddrlen)) {
		std::cout << "ERROR getting server socket local addr" << std::endl;
		return -1;
	}
	struct sockaddr_in* myaddrptr = (struct sockaddr_in*) &myaddr;
	printf("Our address: %s\n", inet_ntoa(myaddrptr->sin_addr));
	printf("Our port in network byte order %d\n", myaddrptr->sin_port);
	printf("Our port: %d\n", ntohs(myaddrptr->sin_port));
	return sockfd;
}

int picoquic_xia_sendmsg(int sockfd, uint8_t* bytes, int length,
		sockaddr_x* peer_addr, sockaddr_x* local_addr)
{
	Graph addr_to(peer_addr);
	Graph addr_from(local_addr);
	// Convert addr to wire format
	// Create XIA Header
	struct click_xia xiah;
	memset(&xiah, 0, sizeof(struct click_xia));
	xiah.ver = 1;
	xiah.nxt = CLICK_XIA_NXT_DATA;
	xiah.plen = length;
	xiah.hlim = HLIM_DEFAULT;
	xiah.dnode = addr_to.num_nodes();
	xiah.snode = addr_from.num_nodes();

	//xiah.snode = myaddr.num_nodes();
	xiah.last = LAST_NODE_DEFAULT;
	int num_nodes = xiah.dnode + xiah.snode;

	// The addresses (dest, src) reside in a separate buffer
	std::vector<click_xia_xid_node> addr_nodes(num_nodes);
	auto dst_nodes = addr_nodes.data();
	auto src_nodes = dst_nodes + xiah.dnode;
	addr_to.fill_wire_buffer(dst_nodes);
	addr_from.fill_wire_buffer(src_nodes);

	// Get the (nearest) XIA router's address
	struct sockaddr_in router_addr;
	if(picoquic_xia_router_addr(&router_addr)) {
		std::cout << "Error getting router address" << std::endl;
		return -1;
	}

	// Combine header, addresses and user provided bytes
	struct iovec parts[3];
	parts[0].iov_base = &xiah;
	parts[0].iov_len = sizeof(xiah);
	parts[1].iov_base = addr_nodes.data();
	parts[1].iov_len = sizeof(click_xia_xid_node) * num_nodes;
	parts[2].iov_base = bytes;
	parts[2].iov_len = length;

	// Now send the packet out to the router
	struct msghdr msg;
	msg.msg_name = &router_addr;
	msg.msg_namelen = sizeof(router_addr);
	msg.msg_iov = parts;
	msg.msg_iovlen = 3;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	int retval = sendmsg(sockfd, &msg, 0);

	return retval;
}

int picoquic_xia_router_addr(struct sockaddr_in* router_addr)
{
	// TODO: fill in the router address from a config file
	// TODO: future calls should just return address without reading.
	memset(router_addr, 0, sizeof(struct sockaddr_in));
	router_addr->sin_port = htons(ROUTER_PORT);
	router_addr->sin_family = AF_INET;
	if(inet_aton(ROUTER_ADDR, &(router_addr->sin_addr)) == 0) {
		std::cout << "Error converting router addr" << std::endl;
		return -1;
	}
	printf("Router Addr: %s\n", inet_ntoa(router_addr->sin_addr));
	return 0;
}

int picoquic_xia_recvfrom(int sockfd, sockaddr_x* addr_from,
		sockaddr_x* addr_local, uint8_t* buffer, int buflen)
{
	// Receive the packet
	struct sockaddr_in router_addr;
	struct msghdr msg;

	// We receive the XIA Header minus DAGs
	struct click_xia xiah;
	// and the DAGs along with payload
	uint8_t addrspluspayload[1532];

	struct iovec parts[2];
	parts[0].iov_base = &xiah;
	parts[0].iov_len = sizeof(xiah);
	parts[1].iov_base = &addrspluspayload;
	parts[1].iov_len = sizeof(addrspluspayload);

	msg.msg_name = &router_addr;
	msg.msg_namelen = sizeof(router_addr);
	msg.msg_iov = parts;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	ssize_t retval = recvmsg(sockfd, &msg, 0);
	if(retval == -1) {
		std::cout << "Error receiving a packet" << std::endl;
		return -1;
	}

	// Extract XIA header from it
	if(xiah.ver != 1 || xiah.nxt != CLICK_XIA_NXT_DATA) {
		std::cout << "Error: invalid packet. Not XIA" << std::endl;
		return -1;
	}

	// Copy over the DAGs to user provided buffers
	int payload_length = xiah.plen;
	const node_t* dst_wire_addr = (const node_t*)&addrspluspayload;
	const node_t* src_wire_addr = dst_wire_addr + xiah.dnode;
	Graph our_addr;
	Graph their_addr;
	our_addr.from_wire_format(xiah.dnode, dst_wire_addr);
	their_addr.from_wire_format(xiah.snode, src_wire_addr);
	our_addr.fill_sockaddr(addr_local);
	their_addr.fill_sockaddr(addr_from);

	// Copy out the payload to user buffer
	int payload_offset = sizeof(node_t) * (xiah.dnode + xiah.snode);
	memcpy(buffer, &(addrspluspayload[payload_offset]), payload_length);
	return 0;
}

int picoquic_xia_select(int sockfd, sockaddr_x* addr_from,
		sockaddr_x* addr_local, uint8_t* buffer, int buflen,
		int64_t delta_t, uint64_t* current_time)
{
	fd_set readfds;
	struct timeval tv;
	int bytes_recv = 0;
	int ret_select;

	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);
	if(delta_t <= 0) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
	} else {
		if(delta_t > 10000000) {
			tv.tv_sec = (long)10;
			tv.tv_usec = 0;
		} else {
			tv.tv_sec = (long)(delta_t / 1000000);
			tv.tv_usec = (long)(delta_t % 1000000);
		}
	}
	ret_select = select(sockfd+1, &readfds, NULL, NULL, &tv);
	if(ret_select < 0) {
		bytes_recv = -1;
		DBG_PRINTF("Error: select on xiaquic sock returns %d\n", ret_select);
	} else if(ret_select > 0) {
		if(FD_ISSET(sockfd, &readfds)) {
			bytes_recv = picoquic_xia_recvfrom(sockfd, addr_from,
					addr_local, buffer, buflen);
			if(bytes_recv <= 0) {
				DBG_PRINTF("Unable to recv on xiaquic sock %d\n", sockfd);
			}
		}
	}
	*current_time = picoquic_current_time();

	return bytes_recv;
}


