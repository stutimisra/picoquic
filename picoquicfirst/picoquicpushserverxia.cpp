#include "localconfig.hpp"
#include "xiapushserver.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};
#include "xiaapi.hpp"
#include "dagaddr.hpp"

#define CONFFILE "localserver.conf"

#define SERVER_AID "SERVER_AID"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8296"
#define CONTROL_IP "172.64.0.31"

#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"
// typedef struct addr_info_t {
// 	int sockfd;
// 	GraphPtr dag;
// 	sockaddr_x addr;
// 	int addrlen;
// };

void print_address(struct sockaddr* address, char* label)
{
	char hostname[256];
	if(address->sa_family == AF_XIA) {
		sockaddr_x* addr = (sockaddr_x*) address;
		Graph dag(addr);
		std::cout << std::string(label) << " "
			<< dag.dag_string() << std::endl;
	} else {
		std::cout << "Invalid address - expected XIA" << std::endl;
	}
	return;
}

// this is for the server data that gets the data
int main()
{
	int retval = -1;
	int state = 0;
	FILE* logfile = NULL;
	uint64_t current_time;
	picoquic_quic_t* server = NULL;
	int64_t delay_max = 10000000;      // max wait 10 sec.
	sockaddr_x addr_from;
	sockaddr_x addr_local;
	unsigned long to_interface = 0;    // our interface
	uint8_t buffer[1536];              // buffer to receive packets
	int bytes_recv;                    // size of packet received
	picoquic_cnx_t* connections = NULL;
	picoquic_cnx_t* next_connection = NULL;
	uint8_t send_buffer[1536];
	size_t send_length = 0;
	unsigned char received_ecn;


	addr_info_t myaddr;
	// LocalConfig conf;

	LocalConfig conf = LocalConfig(CONFFILE);
    // auto xcache_aid = conf.get(XCACHE_AID);
    // auto test_cid = conf.get(TEST_CID);
	std::string xcache_aid = conf.get(XCACHE_AID); // this need not be xcache so we should pass it indvidually 
    std::string test_cid = conf.get(TEST_CID);
	conf.control_addr = CONTROL_IP;
	conf.control_port = CONTROL_PORT;
	addr_info_t peer_addr;




	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, peer_addr) < 0)
	{
		goto server_done;
	}	
	state = 1; // server socket now exists
    picoquic_xia_push_server(xcache_aid, test_cid);
	// Wait for packets
	
	// Server ended cleanly, change return code to success
	retval = 0;

server_done:
	switch(state) {
		case 3: // close the log file
			fclose(logfile);
		case 2: // cleanup QUIC instance
			picoquic_free(server);
		case 1: // cleanup server sockets
			if(myaddr.sockfd != -1) {
				close(myaddr.sockfd);
			}
	};
	return retval;
}
