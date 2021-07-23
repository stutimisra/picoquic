 #include "localconfig.hpp"
// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"
#include "thread"

// C++ includes
#include <iostream>

// C includes
#include <string.h> // memset
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

extern "C" {
#include "picoquic.h" // picoquic_create, states, err, pkt types, contexts
//#include "picoquic_internal.h"
#include "picosocks.h" // picoquic_select and server socks functions
#include "util.h"
};

#define SERVER_CERT_FILE "../certs/cert.pem"
#define SERVER_KEY_FILE "../certs/key.pem"

// server conf
#define SERVERCONFFILE "localserver.conf"
#define SERVER_AID "SERVER_AID"
#define IFNAME "IFNAME"
#define SERVER_CONTROL_PORT "8296"
#define SERVER_CONTROL_IP "172.16.7.3"

// client conf
#define CONFFILE "local.conf"
#define THEIR_ADDR "THEIR_ADDR" // The THEIR_ADDR entry in config file
#define CLIENT_AID "CLIENT_AID" // The CLIENT_AID entry in config file
#define TICKET_STORE "TICKET_STORE"
#define IFNAME "IFNAME"
#define CLIENT_CONTROL_PORT "8295"
#define CLIENT_CONTROL_IP "172.16.7.3"

// If there were multiple streams, we would track progress for them here
struct callback_context_t {
	int connected;
	int stream_open;
	int received_so_far;
	uint64_t last_interaction_time;
};

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
/*
typedef struct {
	int stream_open;     // Assuming just one stream for now
	int received_so_far; // Number of bytes received in that one stream
} callback_context_t;*/

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

//picoquic_stream_data_cb_fn
int client_callback(picoquic_cnx_t* cnx,
		uint64_t stream_id, uint8_t*bytes, size_t length,
		picoquic_call_back_event_t event, void *callback_context)
{
	printf("Client callback\n");

	struct callback_context_t *context =
		(struct callback_context_t*)callback_context;

	context->last_interaction_time = picoquic_current_time();

	switch(event) {
		case picoquic_callback_ready:
			printf("Callback: ready\n");
			break;
		case picoquic_callback_almost_ready:
			printf("Callback: almost_ready\n");
			break;
		case picoquic_callback_close:
			printf("Callback: close\n");
		case picoquic_callback_application_close:
			printf("Callback: application close\n");
		case picoquic_callback_stateless_reset:
			printf("Callback: stateless reset\n");
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_reset:
			printf("Callback: stream reset\n");
		case picoquic_callback_stop_sending:
			printf("Callback: stop_sending\n");
			picoquic_reset_stream(cnx, stream_id, 0);
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_gap:
			printf("Callback: stream gap\n");
			picoquic_reset_stream(cnx, stream_id,
					PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
			context->stream_open = 0;
			return 0;
		case picoquic_callback_stream_data:
			printf("Callback: no event\n");
			if(length > 0) {
				char data[256];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			break;
		case picoquic_callback_stream_fin:
			printf("Callback: stream finished\n");
			if(length > 0) {
				char data[256];
				memcpy(data, (char*)bytes, length);
				data[length] = 0;
				printf("Server sent: %s\n", data);
				context->received_so_far += length;
			}
			context->stream_open = 0;
			printf("Reception completed after %d bytes.\n",
					context->received_so_far);
			printf("Resetting the stream after it finished.\n");
			picoquic_reset_stream(cnx, stream_id, 0);
			/*
			// Closing connection immediately
			printf("Closing connection after stream ended\n");
			picoquic_close(cnx, 0);
			*/
			break;
		default:
			printf("ERROR: unknown callback event %d\n", event);
	};
	return 0;
}

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

void* picoquic_client(void* arg) {
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
		conf.control_addr = CLIENT_CONTROL_IP;
		conf.control_port = CLIENT_CONTROL_PORT;
		addr_info_t myaddr;
		addr_info_t serveraddr;
		std::string ticket_store_filename;
		if(conf.configure(CLIENT_CONTROL_PORT, CLIENT_CONTROL_IP, myaddr, serveraddr) < 0)
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

		// Callback context
		struct callback_context_t callback_context;
		memset(&callback_context, 0, sizeof(struct callback_context_t));

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

		// Create a connection in QUIC
		picoquic_cnx_t *connection;
		connection = picoquic_create_cnx(
				client, // QUIC context
				picoquic_null_connection_id,        // initial connection ID
				picoquic_null_connection_id,        // remote_connection ID
				(struct sockaddr*) &serveraddr.addr, // Address to
				current_time,   // start time
				0,              // preferred version
				"localhost",    // Server name identifier
				"hq-17",        // ALPN
				1           	// client mode, set to 1, if on client side
				);
		if(connection == NULL) {
			printf("ERROR: creating client connection in QUIC\n");
			goto client_done;
		}
		printf("Created QUIC connection instance\n");
		state = 4;

		// Set a callback for the client connection
		// TODO: Can we just set the callback in picoquic_create?
		picoquic_set_callback(connection, client_callback, &callback_context);

		// Now connect to the server
		if(picoquic_start_client_cnx(connection)) {
			printf("ERROR: connecting to server\n");
			goto client_done;
		}
		printf("Started connection to server\n");

		// If 0RTT is available, start a stream
		if(picoquic_is_0rtt_available(connection)) {
			start_stream(connection, &callback_context);
			zero_rtt_available = 1;
		}
		printf("Zero RTT available: %d\n", zero_rtt_available);

		pthread_mutex_lock(&conf.lock);
		// Send a packet to get the connection establishment started
		if(picoquic_prepare_packet(connection, current_time,
					send_buffer, sizeof(send_buffer), &send_length,
					(struct sockaddr_storage*)&serveraddr.addr, &serveraddr.addrlen,
					(struct sockaddr_storage*)&myaddr.addr, &myaddr.addrlen)) {
			printf("ERROR: preparing a QUIC packet to send\n");
			pthread_mutex_unlock(&conf.lock);
			goto client_done;
		}
		printf("Prepared packet of size %zu\n", send_length);
		myaddr.dag->fill_sockaddr(&myaddr.addr);
		int bytes_sent;
		if(send_length > 0) {
			bytes_sent = picoquic_xia_sendmsg(myaddr.sockfd, send_buffer,
					(int) send_length, &serveraddr.addr, &myaddr.addr, conf);
			if(bytes_sent < 0) {
				printf("ERROR: sending packet to server\n");
				goto client_done;
			}
			printf("Sent %d byte packet to server: %s) from me: %s\n", bytes_sent,
			 serveraddr.dag->dag_string().c_str(), myaddr.dag->dag_string().c_str());
		}
		pthread_mutex_unlock(&conf.lock);

		// Wait for incoming packets
		while(picoquic_get_cnx_state(connection) != picoquic_state_disconnected) {

			delay_max = 10000000;

			// Wait until data or timeout
			bytes_recv = picoquic_xia_select(myaddr.sockfd, &packet_from,
					&packet_to, buffer, sizeof(buffer),
					delta_t,
					&current_time);

			// Exit on error
			if(bytes_recv < 0) {
				printf("ERROR: receiving packet after select\n");
				goto client_done;
			}

			// Get the connection state
			picoquic_state_enum cnx_state = picoquic_get_cnx_state(connection);
			printf("Connection state: %d\n", cnx_state);

			// We have a packet to process
			if(bytes_recv > 0) {
				printf("Got %d byte packet\n", bytes_recv);
				// TODO: it seems this function always returns 0
				if(picoquic_incoming_packet(client, buffer,
							(size_t)bytes_recv, (struct sockaddr*)&packet_from,
							(struct sockaddr*)&packet_to, if_index_to,
							received_ecn,
							current_time)) {
					printf("ERROR: processing incoming packet\n");
					delta_t = 0;
				}
				delta_t = 0;
			}

			// Timed out. Check if connection established or stream ended
			if(bytes_recv == 0) {
				if(cnx_state == picoquic_state_ready
						|| cnx_state == picoquic_state_client_ready_start) {

					// The connection is ready. Start a stream.
					if(!established) {
						printf("Connected! ver: %x, I-CID: %llx\n",
								picoquic_supported_versions[
								connection->version_index].version,
								(unsigned long long)picoquic_val64_connection_id(
									picoquic_get_logging_cnxid(connection)));
						if(!zero_rtt_available) {
							printf("zero rtt was not available, starting stream\n");
							start_stream(connection, &callback_context);
						}
						established = 1;
					}
				}

				// If the stream has been closed, we close the connection
				if(callback_context.connected && !callback_context.stream_open) {
					printf("The stream was not open, close connection\n");
					picoquic_close(connection, 0);
					connection = NULL;
					break;
				}

				// Waited too long. Close connection
				if(current_time > callback_context.last_interaction_time
						&& current_time - callback_context.last_interaction_time
						    > 60000000ull) {
					printf("No progress for 60 seconds. Closing\n");
					picoquic_close(connection, 0);
					connection = NULL;
					break;
					//goto client_done;
				}
			}

			// We get here whether there was a packet or a timeout
			send_length = PICOQUIC_MAX_PACKET_SIZE;
			while(send_length > 0) {
				//sleep(5); // add a delay make sure the configuration updates
				// Send out all packets waiting to go
				pthread_mutex_lock(&conf.lock);
				if(picoquic_prepare_packet(connection, current_time,
							send_buffer, sizeof(send_buffer), &send_length,
							NULL, NULL, NULL, NULL)) {
					printf("ERROR sending QUIC packet\n");
					pthread_mutex_unlock(&conf.lock);
					goto client_done;
				}
				if(send_length > 0) {
					printf("Sending packet of size %ld\n", send_length);
					bytes_sent = picoquic_xia_sendmsg(myaddr.sockfd, send_buffer,
							(int) send_length, &serveraddr.addr, &myaddr.addr, conf);
					//printf("Sending a packet of size %d\n", (int)send_length);
					if(bytes_sent <= 0) {
						printf("ERROR sending packet to server\n");
					}
					printf("Sent %d byte packet to server: %s) from me: %s\n", bytes_sent, 
						serveraddr.dag->dag_string().c_str(), myaddr.dag->dag_string().c_str());
				}
				pthread_mutex_unlock(&conf.lock);
			}

			// How long before we timeout waiting for more packets
			delta_t = picoquic_get_next_wake_delay(client, current_time,
					delay_max);

		}
		// Save tickets from server, so we can join quickly next time
		if(picoquic_save_tickets(client->p_first_ticket, current_time,
					ticket_store_filename.c_str()) != 0) {
			printf("ERROR saving session tickets\n");
		}
		// Everything went well, so return success
		retval = 0;

	client_done:
		switch(state) {
			case 4:
				if(connection) {
					picoquic_close(connection, 0); // 0 = reason code
				}
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

	return NULL;

}

void* picoquic_server(void* arg) {
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
		//int sockfd = -1;

		// auto conf = LocalConfig::get_instance(CONFFILE);
		// auto server_aid = conf.get(SERVER_AID);
		// std::string server_ifname = conf.get(IFNAME);
		
		// // We give a fictitious AID for now, and get a dag in my_addr
		// std::cout<<"Xia open server"<<std::endl;
		//  = picoquic_xia_open_server_socket(server_aid.c_str(), my_addr, server_ifname);
		// if(sockfd == -1) {
		// 	printf("ERROR creating xia server socket\n");
		// 	return -1;
		// } else {
		// 	printf("SUCCESS creating xia server socket\n");
		// }
		// LocalConfig conf;
		// GraphPtr mydag;
		// int my_addrlen;
		// sockaddr_x my_addr;
		addr_info_t myaddr;
		LocalConfig conf;
		conf.control_addr = SERVER_CONTROL_IP;
		conf.control_port = SERVER_CONTROL_PORT;
		addr_info_t peer_addr;
		if(conf.configure(SERVER_CONTROL_PORT, SERVER_CONTROL_IP, myaddr, peer_addr) < 0)
		{
			goto server_done;
		}	
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

			printf("Going into select\n");

			bytes_recv = picoquic_xia_select(myaddr.sockfd, &addr_from,
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
				//char label[] = "Server: client addr:";
				//print_address((struct sockaddr*)&addr_from, label);
				(void)picoquic_incoming_packet(server, buffer,
						(size_t)bytes_recv, (struct sockaddr*)&addr_from,
						(struct sockaddr*)&addr_local, to_interface,
						received_ecn,
						current_time);
				//printf("Server: processed incoming packet through QUIC\n");
				//print_address((struct sockaddr*)&addr_from, label);
				//char label2[] = "Server: server addr:";
				//print_address((struct sockaddr*)&addr_local, label2);
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
				if(sp->addr_to.sx_family != AF_XIA) {
					std::cout << "ERROR: Non XIA stateless packet" << std::endl;
					break;
				}
				// send out any outstanding stateless packets
				printf("Server: sending stateless packet out on network\n");
				picoquic_xia_sendmsg(myaddr.sockfd, sp->bytes, sp->length,
						&sp->addr_to, &sp->addr_local, conf);
				picoquic_delete_stateless_packet(sp);
			}

			// ms outgoing packets for all connections
			while((next_connection = picoquic_get_earliest_cnx_to_wake(server,
						loop_time)) != NULL) {
				sockaddr_x peer_addr;
				sockaddr_x local_addr;
				int peer_addr_len = sizeof(sockaddr_x);
				int local_addr_len = sizeof(sockaddr_x);
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
						(void)picoquic_xia_sendmsg(myaddr.sockfd,
								send_buffer, send_length,
								&peer_addr, &local_addr, conf);
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
				if(myaddr.sockfd != -1) {
					close(myaddr.sockfd);
				}
		};
	return NULL;
}

int main(int argc, char** argv)
{
	/*
	if (argc != 2) {
		std::cout << "Please specify client or server" << std::endl;
		exit(0);
	}*/

	int error = 0;
	pthread_t tid[2];

    error = pthread_create(&(tid[0]), NULL, &picoquic_server, NULL);
    if (error != 0)
        printf("\nServer can't be created : [%s]", strerror(error));
  
  	error = 0;


    error = pthread_create(&(tid[1]), NULL, &picoquic_client, NULL);
    if (error != 0)
        printf("\nClient can't be created : [%s]", strerror(error));

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);


	//if (strcmp(argv[1], "client") == 0) {

    return 1;
	//} else {

	//}
}
