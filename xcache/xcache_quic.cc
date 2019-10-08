#include <xcache_quic.h>

extern "C" {
#include "picosocks.h"
#include "util.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
};

#include <iostream>
#include <memory>

XcacheQUIC::XcacheQUIC(picoquic_stream_data_cb_fn callback, QUIC_ROLE instance_role) {
	const char *server_cert_file = NULL;
	const char *server_key_file = NULL;
	const char *client_ticket_file = NULL;
	const char *client_alpn = NULL;
	role = instance_role;

	if (role == XCACHE_SERVER) {
		server_cert_file = SERVER_CERT_FILE;
		server_key_file = SERVER_KEY_FILE;

	} else {
		client_ticket_file = CLIENT_TICKET_FILE;
		client_alpn = CLIENT_ALPN;
	}

	picoquic_quic_t* s = picoquic_create(8, // number of connections
			server_cert_file,
			server_key_file,
			NULL,               // cert_root_filename
			client_alpn,        // Appl. Layer Protocol Negotiation (ALPN)
			callback,           // Stream data callback
			NULL,               // Stream data context
			NULL,               // Connection ID callback
			NULL,               // Connection ID callback context
			NULL,               // reset seed
			current_time,
			NULL,               // p_simulated time
			client_ticket_file, // ticket_file_name
			NULL,               // ticket_encryption_key
			0                   // ticket encryption key length
			);
	if (s == NULL) {
		throw "ERROR creatking QUIC instance";
	}
	server = PicoquicPtr(s, &picoquic_free);
	logfile = FilePtr(fopen(LOGFILENAME, "w"), &fclose);
	if (logfile == nullptr) {
		throw "ERROR opening logfile";
	}
	PICOQUIC_SET_LOG(server.get(), logfile.get());
}

void XcacheQUIC::updateTime() {
	current_time = picoquic_current_time();
}

int64_t XcacheQUIC::nextWakeDelay(int64_t delay_max) {
	return picoquic_get_next_wake_delay(server.get(),
			current_time, delay_max);
}

int XcacheQUIC::incomingPacket(uint8_t* bytes, uint32_t packet_length,
	  struct sockaddr* addr_from, struct sockaddr* addr_to,
	  int if_index_to, unsigned char received_ecn) {
	return picoquic_incoming_packet(server.get(), bytes, packet_length,
			addr_from, addr_to, if_index_to, received_ecn, current_time);
}

uint64_t XcacheQUIC::currentTime() {
	return current_time;
}

picoquic_cnx_t* XcacheQUIC::firstConnection() {
	return picoquic_get_first_cnx(server.get());
}

picoquic_stateless_packet_t* XcacheQUIC::dequeueStatelessPacket() {
	return picoquic_dequeue_stateless_packet(server.get());
}

picoquic_cnx_t* XcacheQUIC::earliestConnection() {
	return picoquic_get_earliest_cnx_to_wake(server.get(), current_time);
}

#if 0
std::string XcacheQUIC::serverCertFile() {
	return inputPath(SERVER_CERT_FILE);
}

std::string XcacheQUIC::serverKeyFile() {
	return inputPath(SERVER_KEY_FILE);
}
#endif

std::string XcacheQUIC::inputPath(std::string filename) {
	char buf[1024];
	if(picoquic_get_input_path(buf, sizeof(buf), NULL, filename.c_str())) {
		std::string errmsg = "ERROR finding path for" + filename;
		throw errmsg;
	}
	std::string result(buf);
	return result;
}
