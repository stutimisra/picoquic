 #include "localconfig.hpp"
// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"
#include "xiapushclient.hpp"

// C++ includes
#include <iostream>

// C includes
#include <string.h> // memset
#include <stdio.h>
#include <pthread.h>

extern "C" {
#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"
};

#define CONFFILE "local.conf"
#define THEIR_ADDR "THEIR_ADDR" // The THEIR_ADDR entry in config file
#define CLIENT_AID "CLIENT_AID" // The CLIENT_AID entry in config file
#define TICKET_STORE "TICKET_STORE"
#define IFNAME "IFNAME"
#define CONTROL_PORT "8295"
#define CONTROL_IP "10.0.1.131"

// Move this logic to the stri
void start_stream(picoquic_cnx_t* connection,
		struct callback_context_t* context)
{
	printf("Starting a stream\n");

	uint64_t stream_id = 0;
	char data[] = "Hello world!";
	context->stream_open = 1;
	context->connected = 1;

	// Queue up a "Hello world!" to be sent to the server
	printf("Sending %ld bytes of data on stream\n", sizeof(data));
	if(picoquic_add_to_stream(connection,
				stream_id, // Any arbitrary stream ID client picks
				(uint8_t*)data, sizeof(data), // data to be sent
				1)) { // finished; would be 0 if interacting more with server
		printf("ERROR: sending hello on stream\n");
	}
}

int main()
{
	// cleanup state
	int state = 0;
	int retval = -1;
	FILE* logfile = NULL;

	// Event loop parameters
	int64_t delay_max = 10000000;
	sockaddr_x packet_from;
	sockaddr_x packet_to;
	unsigned long if_index_to = 0;
	uint8_t buffer[1536];
	int bytes_recv;
	int64_t delta_t = 0;
	//int notified_ready = 0;
	int established = 0;
	unsigned char received_ecn;
	uint64_t current_time;
	int zero_rtt_available = 0; // Flag set to 1 if 0RTT is available

	// Outgoing packet buffer
	uint8_t send_buffer[1536];
	size_t send_length = 0;

	// read local config
	
	//server
	// sockaddr_x server_address;
	// std::string serverdagstr = SERVER_ADDR + " " + SERVER_AID;
	// Graph serverdag(serverdagstr);
	// serverdag.fill_sockaddr(&server_address);
	// int server_addrlen = sizeof(sockaddr_x);

	// 
	LocalConfig conf;
	conf.control_addr = CONTROL_IP;
	conf.control_port = CONTROL_PORT;
	addr_info_t myaddr;
	addr_info_t serveraddr;
	std::string ticket_store_filename;
	if(conf.configure(CONTROL_PORT, CONTROL_IP, myaddr, serveraddr) < 0)
	{
		goto client_done;
	}

	// Server address  - keeping that fixed
	// auto server_addr = conf.get_their_addr();
	// auto server_aid = conf.get_server_aid();
	// int server_addrlen;

	// auto conf = LocalConfig::get_instance(CONFFILE);
	// auto server_addr = conf.get(THEIR_ADDR);
	// auto server_aid = conf.get(SERVER_AID);
	// auto client_aid = conf.get(CLIENT_AID);
	// std::string client_ifname = conf.get(IFNAME);
	ticket_store_filename = TICKET_STORE; //conf.get_ticket_store();

	// // QUIC client
	picoquic_quic_t *client;



	// // A socket to talk to server on
	// //sockfd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	// // bind to socket and fill my addr
	// sockfd = picoquic_xia_open_server_socket(client_aid.c_str(), mydag, client_ifname);
	// if(sockfd == INVALID_SOCKET) {
	// 	goto client_done;
	// }
	// std::cout << "CLIENTADDR: " << mydag->dag_string().c_str() << std::endl;
	// mydag->fill_sockaddr(&my_address);
	// my_addrlen = sizeof(sockaddr_x);
	// printf("Created socket to talk to server\n");
	state = 1; // socket created

	// Create QUIC context for client
	current_time = picoquic_current_time();
	callback_context.last_interaction_time = current_time;
	client = picoquic_create(
			8,             // number of connections
			NULL,          // cert_file_name
			NULL,          // key_file_name
			NULL,          // cert_root_file_name
			"hq-17",       // Appl. Layer Protocol Nogotiation
			NULL,          // Stream data callback
			NULL,          // Stream data context
			NULL,          // connection ID callback
			NULL,          // connection ID callback context
			NULL,          // reset_seed
			current_time,  // current time
			NULL,          // p_simulated_time
			ticket_store_filename.c_str(),          // ticket_file_name
			NULL,          // ticket_encryption_key
			0              // ticket encryption key length
			);

	if(client == NULL) {
		printf("ERROR: creating client\n");
		goto client_done;
	}
	printf("Created QUIC context\n");
	state = 2; // picoquic context created for client

	// Open a log file for writing
	logfile = fopen("client.log", "w");
	if(logfile == NULL) {
		printf("ERROR opening log file\n");
		goto client_done;
	}
	PICOQUIC_SET_LOG(client, logfile);
	state = 3; // logfile needs to be closed

	// We didn't provide a root cert, so set verifier to null
	picoquic_set_null_verifier(client);

	if (picoquic_xia_push_client(client, myaddr, serveraddr, conf.control_addr, conf.control_port, conf) == 0) {
		state = 3; // everything done successfully and logfile needs to close
	} else {
		printf("Error while pushing");
	}

client_done:
	switch(state) {
		case 3:
			fclose(logfile);
			// fallthrough
		case 2:
			picoquic_free(client);
			// fallthrough
		case 1:
			// TODO: Need to unregister this socket and AID at router
			close(myaddr.sockfd);
	};

	return retval;
}
