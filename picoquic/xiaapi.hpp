#ifndef PICOQUIC_XIAAPI_H
#define PICOQUIC_XIAAPI_H

#include "dagaddr.hpp"
#include <memory>

// The QUIC-XIA API
//
// On server side:
// QUIC-XIA app opens a UDP socket and registers it with an XIA router
// An XIA DAG is assigned to this socket.
// The XIA router is set up to forward packets to this socket
//
// picoquic_xia_select: to wait for packets to arrive
// picoquic_xia_sendmsg: to send out UDP packet with XIA header
//

using GraphPtr = std::unique_ptr<Graph>;
using NodePtr = std::unique_ptr<Node>;

//extern "C" int picoquic_xia_open_server_socket(char* aid);

//Returns a socket descriptor and an XIA address, with 'aid' as intent
int picoquic_xia_open_server_socket(const char* aid, GraphPtr& my_addr);

// Get the IP address of an XIA Router we can send packets to
int picoquic_xia_router_addr(struct sockaddr_in* router_addr);
int picoquic_xia_router_control_addr(struct sockaddr_in* router_addr);

// Wait on a socket until data is available or timeout
// Extract src and dest DAGs from the received XIA packet
// Update timestamp
//
// Returns:
// addr_from: Sender DAG
// addr_local: Our DAG (as used by sender)
// buffer: The QUIC encrypted payload and its length
// current_time: The updated timestamp
int picoquic_xia_select(int sockfd, sockaddr_x* addr_from,
		sockaddr_x* addr_local, uint8_t* buffer, int buflen,
		int64_t delta_t, uint64_t*current_time);

// Builds an XIA Packet and sends it to an XIA router, over IP
// ,----------------------------------------,
// |  IP Header  |  XIA Header  |  Payload  |
// '----------------------------------------'
int picoquic_xia_sendmsg(int sockfd, uint8_t* bytes, int length,
		sockaddr_x* peer_addr, sockaddr_x* local_addr);

// Receive a packet from an XIA Router and extract XIA header info and payload
int picoquic_xia_recvfrom(int sockfd, sockaddr_x* addr_from,
		sockaddr_x* addr_local, uint8_t*buffer, int buflen);

// Ask router to set a forwarding table entry for CID to xcachesockfd
// Returns DAG for CID that can be used to request the CID
// Currently, there is no check to ensure CID is on disk.
int picoquic_xia_serve_cid(int xcachesockfd, char* cid, GraphPtr& cid_addr);

#endif //PICOQUIC_XIAAPI_H
