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

#define SERVER_PORT 4443
#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

void print_address(struct sockaddr* address, char* label)
{
	char hostname[256];

	const char *x = inet_ntop(address->sa_family,
			(address->sa_family == AF_INET) ?
			(void*)&(((struct sockaddr_in*)address)->sin_addr) :
			(void*)&(((struct sockaddr_in6*)address)->sin6_addr),
			hostname, sizeof(hostname));
	int port = (address->sa_family == AF_INET) ?
		((struct sockaddr_in*)address)->sin_port :
		((struct sockaddr_in6*)address)->sin6_port;
	port = ntohs(port);
	printf("%s %s, port %d\n", label, x, port);
}

typedef struct {
	int stream_open;     // Assuming just one stream for now
	int received_so_far; // Number of bytes received in that one stream
} callback_context_t;

static int server_callback(picoquic_cnx_t* connection,
		uint64_t stream_id, uint8_t* bytes, size_t length,
		picoquic_call_back_event_t event, void* ctx)
{
	printf("ServerCallback: stream: %lu, len: %zu, event: %d\n",
			stream_id, length, event);
	callback_context_t* context = (callback_context_t*)ctx;

	switch(event) {
		case picoquic_callback_ready:
			printf("ServerCallback: Ready\n");
			break;
		case picoquic_callback_almost_ready:
			printf("ServerCallback: AlmostReady\n");
			break;
		// Handle the connection related events
		case picoquic_callback_close:
			printf("ServerCallback: Close\n");
		case picoquic_callback_application_close:
			printf("ServerCallback: ApplicationClose\n");
		case picoquic_callback_stateless_reset:
			printf("ServerCallback: StatelessReset\n");
			if(context != NULL) {
				// Free the context memory and set it NULL for callback
				free(context);
				picoquic_set_callback(connection, server_callback, NULL);
				printf("ServerCallback: need to free context\n");
			}
			return 0;

		// Handle the stream related events
		case picoquic_callback_prepare_to_send:
			// Unexpected call
			printf("ServerCallback: PrepareToSend\n");
			return -1;
		case picoquic_callback_stop_sending:
			printf("ServerCallback: StopSending: resetting stream\n");
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_reset:
			printf("ServerCallback: StreamReset: resetting stream\n");
			picoquic_reset_stream(connection, stream_id, 0);
			return 0;
		case picoquic_callback_stream_gap:
			printf("ServerCallback: StreamGap\n");
			// This is not supported by picoquic yet
			picoquic_reset_stream(connection, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			return 0;
		case picoquic_callback_stream_data:
			printf("ServerCallback: StreamData\n");
		case picoquic_callback_stream_fin:
			printf("ServerCallback: StreamFin\n");
			if(event == picoquic_callback_stream_fin && length == 0) {
				printf("ServerCallback: StreamFin - resetting!\n");
				picoquic_reset_stream(connection, stream_id,
						PICOQUIC_TRANSPORT_STREAM_STATE_ERROR);
				return 0;
			}
			// If there's to context, create one
			if(!context) {
				printf("ServerCallback: creating a new context for stream\n");
				callback_context_t *new_context = (callback_context_t*)malloc(
						sizeof(callback_context_t));
				if(new_context) {
					memset(new_context, 0, sizeof(callback_context_t));
				} else {
					printf("ERROR creating context in callback\n");
					picoquic_close(connection, PICOQUIC_ERROR_MEMORY);
					return 0;
				}
				// Assign the context to this callback for future triggers
				picoquic_set_callback(connection, server_callback,
						new_context);
				context = new_context;
				if(length > 0) {
					char data[length+1];
					memcpy(data, bytes, length);
					data[length] = 0;
					printf("ServerCallback: Client sent: %s\n", data);
					context->received_so_far += length;
					// Send it back to client and FIN the stream
					(void)picoquic_add_to_stream(connection, stream_id,
							(uint8_t*)data, length, 1);
				}
			}
			if(event != picoquic_callback_stream_data) {
				printf("ServerCallback: StreamFin\n");
				printf("ServerCallback: Client sent %d bytes before ending\n",
						context->received_so_far);
			}
			break;
	};
	return 0;
}

int main()
{
	int retval = -1;
	int state = 0;
	FILE* logfile = NULL;
	uint64_t current_time;
	picoquic_quic_t* server = NULL;
	int64_t delay_max = 10000000;      // max wait 10 sec.
	/*
	struct sockaddr_storage addr_from; // client's address
	struct sockaddr_storage addr_to;   // our address
	socklen_t from_length = sizeof(struct sockaddr_storage);
	socklen_t to_length = sizeof(struct sockaddr_storage);
	*/
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
	char aid[] = "AID:69a4e068880cd40549405dfda6e794b0c7fdf192";
	GraphPtr my_addr;
	int sockfd = -1;
	
	// We give a fictitious AID for now, and get a dag in my_addr
	sockfd = picoquic_xia_open_server_socket(aid, my_addr);
	if(sockfd == -1) {
		printf("ERROR creating xia server socket\n");
	} else {
		printf("SUCCESS creating xia server socket\n");
	}
	std::string addrstr("RE AD:abcd1234abcd1234abcdabcd1234abcd1234abcd HID:abcd1234abcd1234abcdabcd1234abcd1234abcd");
	Graph g(addrstr);
	std::cout << "Address: " << g.dag_string() << std::endl;
	// Create server sockets
	/*
	picoquic_server_sockets_t server_sockets;
	if(picoquic_open_server_sockets(&server_sockets, SERVER_PORT)) {
		printf("ERROR creating server sockets\n");
		goto server_done;
	}
	*/
	state = 1; // server socket now exists

	// Get the server certificate
	char server_cert_file[512];
	if(picoquic_get_input_path(server_cert_file, sizeof(server_cert_file),
				NULL, SERVER_CERT_FILE)) {
		printf("ERROR finding server certificate\n");
		goto server_done;
	}

	// Get the server crypto key
	char server_key_file[512];
	if(picoquic_get_input_path(server_key_file, sizeof(server_key_file),
				NULL, SERVER_KEY_FILE)) {
		printf("ERROR finding server key file\n");
		goto server_done;
	}

	// Create QUIC instance
	current_time = picoquic_current_time();
	server = picoquic_create(8, // number of connections
			server_cert_file,
			server_key_file,
			NULL,                // cert_root_file_name
			NULL,                // Appl. Layer Protocol Negotiation (ALPN)
			server_callback,     // Stream data callback
			NULL,                // Stream data context - assigned in callback
			NULL, // Connection ID callback
			NULL,                // Connection ID callback context
			NULL,                // reset seed
			current_time,
			NULL,                // p_simulated_time
			NULL,                // ticket_file_name
			NULL,                // ticket_encryption_key
			0                    // ticket encryption key length
			);
	if(server == NULL) {
		printf("ERROR creating QUIC instance for server\n");
		goto server_done;
	}
	state = 2;

	// Open a log file
	logfile = fopen("server.log", "w");
	if(logfile == NULL) {
		printf("ERROR creating log file\n");
		goto server_done;
	}
	state = 3;
	PICOQUIC_SET_LOG(server, logfile);

	// Wait for packets
	while(1) {
		int64_t delta_t = picoquic_get_next_wake_delay(server, current_time,
				delay_max);

		/*
		bytes_recv = picoquic_select(server_sockets.s_socket,
				PICOQUIC_NB_SERVER_SOCKETS,
				&addr_from, &from_length,
				&addr_to, &to_length, &to_interface,
				&received_ecn,
				buffer, sizeof(buffer),
				delta_t,
				&current_time);
				*/
		bytes_recv = picoquic_xia_select(sockfd, &addr_from,
				&addr_local, buffer, sizeof(buffer),
				delta_t,
				&current_time);
		if(bytes_recv < 0) {
			printf("Server: ERROR selecting on client requests\n");
			goto server_done;
		}

		uint64_t loop_time;
		if(bytes_recv > 0) {
			// Process the incoming packet via QUIC server
			printf("Server: got %d bytes from client\n", bytes_recv);
			char label[] = "Server: client addr:";
			print_address((struct sockaddr*)&addr_from, label);
			(void)picoquic_incoming_packet(server, buffer,
					(size_t)bytes_recv, (struct sockaddr*)&addr_from,
					(struct sockaddr*)&addr_local, to_interface,
					received_ecn,
					current_time);
			printf("Server: processed incoming packet through QUIC\n");
			// If we don't have a list of server connections, get it
			if(connections==NULL
					|| connections!=picoquic_get_first_cnx(server)) {
				printf("Server: New connection\n");
				connections = picoquic_get_first_cnx(server);
				if(connections == NULL) {
					printf("ERROR: No connection found!\n");
					goto server_done;
				}
				printf("Server: Connection established\n");
				printf("Server: Connection state = %d\n",
						picoquic_get_cnx_state(connections));

			}
		}
		loop_time = current_time;

		// Send stateless packets
		picoquic_stateless_packet_t* sp;
		while((sp = picoquic_dequeue_stateless_packet(server)) != NULL) {
			printf("Server: found a stateless packet to send\n");
			if(sp->addr_to.ss_family != AF_XIA) {
				std::cout << "ERROR: Non XIA stateless packet" << std::endl;
				break;
			}
			// Get address lengths
			/*
			socklen_t to_len = sizeof(struct sockaddr_in);
			socklen_t local_len = sizeof(struct sockaddr_in);
			if(sp->addr_to.ss_family != AF_INET) {
				to_len = sizeof(struct sockaddr_in6);
			}
			if(sp->addr_local.ss_family != AF_INET) {
				local_len = sizeof(struct sockaddr_in6);
			}
			*/
			// send out any outstanding stateless packets
			printf("Server: sending stateless packet out on network\n");
			picoquic_xia_sendmsg(sockfd, sp->bytes, sp->length,
					&sp->addr_to, &sp->addr_local);
			/*
			(void)picoquic_send_through_server_sockets(&server_sockets,
					(struct sockaddr*)&sp->addr_to, to_len,
					(struct sockaddr*)&sp->addr_local, local_len,
					sp->if_index_local,
					(const char*)sp->bytes, (int)sp->length);
					*/
			picoquic_delete_stateless_packet(sp);
		}

		// Send outgoing packets for all connections
		while((next_connection = picoquic_get_earliest_cnx_to_wake(server,
					loop_time)) != NULL) {
			//struct sockaddr_storage peer_addr;
			sockaddr_x peer_addr;
			sockaddr_x local_addr;
			int peer_addr_len = 0;
			int local_addr_len = 0;
			//struct sockaddr_storage local_addr;
			// Ask QUIC to prepare a packet to send out on this connection
			//
			// TODO: HACK!!! peer and local addr pointers sent as
			// sockaddr_storage so underlying code won't complain.
			// Fix would require changes to picoquic which we want to avoid
			int rc = picoquic_prepare_packet(next_connection, current_time,
					send_buffer, sizeof(send_buffer), &send_length,
					(struct sockaddr_storage*) &peer_addr, &peer_addr_len,
					(struct sockaddr_storage*) &local_addr, &local_addr_len);
			if(rc == PICOQUIC_ERROR_DISCONNECTED) {
				// Connections list is empty, if this was the last connection
				if(next_connection == connections) {
					connections = NULL;
				}
				printf("Server: Disconnected!\n");
				picoquic_delete_cnx(next_connection);
				// All connections ended, break out of outgoing packets loop
				break;
			}
			if(rc == 0) {
				if(send_length > 0) {
					printf("Server: sending %ld byte packet\n", send_length);
					(void)picoquic_xia_sendmsg(sockfd,
							send_buffer, send_length,
							&peer_addr, &local_addr);

					/*
					(void)picoquic_send_through_server_sockets(
							&server_sockets,
							(struct sockaddr*)&peer_addr, peer_addr_len,
							(struct sockaddr*)&local_addr, local_addr_len,
							picoquic_get_local_if_index(next_connection),
							(const char *)send_buffer, (int)send_length);
							*/
				}
			} else {
				printf("Server: Exiting outgoing pkts loop. rc=%d\n", rc);
				break;
			}
		}
	}
	// Server ended cleanly, change return code to success
	retval = 0;

server_done:
	switch(state) {
		case 3: // close the log file
			fclose(logfile);
		case 2: // cleanup QUIC instance
			picoquic_free(server);
		case 1: // cleanup server sockets
			if(sockfd != -1) {
				close(sockfd);
			}
	};
	return retval;
}
