#ifndef _XCACHE_QUIC_H_
#define _XCACHE_QUIC_H_

// QUIC includes
extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
};

// C++ standard includes
#include <string>
#include <memory>
#include <vector> // FIXME: switch to string???

// XIA Includes
#include "publisher/publisher.h"
#include "headers/content_header.h"

#include "xiaapi.hpp"

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"
#define CLIENT_TICKET_FILE "/tmp/xcache_ticket_store.bin"
#define CLIENT_ALPN "hq-17"
#define LOGFILENAME "xcache.log"

enum QUIC_ROLE {XCACHE_SERVER, XCACHE_CLIENT};

using PicoquicPtr = std::unique_ptr<picoquic_quic_t,
	  decltype(&picoquic_free)>;

using FilePtr = std::unique_ptr<FILE, decltype(&fclose)>;

// FIXME: this shouldn't go here
enum class ChunkState {INITIAL, FETCHING_HEADER, FETCHING_DATA, READY};
struct chunk {
	ChunkState state = ChunkState::INITIAL;
	int hdr_len = -1;
	std::vector<uint8_t> buf;
	std::unique_ptr<ContentHeader> chdr;
	std::unique_ptr<uint8_t> data;
};



typedef struct {
	int stream_open;
	int received_so_far;
	std::vector<uint8_t> data;
	size_t datalen;
	size_t recv_offset;		// FIXME: do i need this??
	size_t sent_offset;		// FIXME: do i need this??
	NodePtr xid;

	// added from client code
	uint64_t last_interaction_time;
	std::unique_ptr<struct chunk> chunk;
} callback_context_t;



class XcacheQUIC {
	public:
		XcacheQUIC(picoquic_stream_data_cb_fn callback, QUIC_ROLE instance_roll);
		void updateTime();
		int64_t nextWakeDelay(int64_t delay_max);
		int incomingPacket(uint8_t* bytes, uint32_t packet_length,
				struct sockaddr* addr_from, struct sockaddr* addr_to,
				int if_index_to, unsigned char received_ecn);
		uint64_t currentTime();
		picoquic_cnx_t* firstConnection();
		picoquic_stateless_packet_t* dequeueStatelessPacket();
		picoquic_cnx_t* earliestConnection();

	private:
		void init();
//		std::string serverCertFile();
//		std::string serverKeyFile();
		std::string inputPath(std::string filename);

//		std::string server_key_file;
//		std::string server_cert_file;
		PicoquicPtr server = PicoquicPtr(nullptr, &picoquic_free);
		FilePtr logfile = FilePtr(nullptr, &fclose);
		uint64_t current_time;
		QUIC_ROLE role;
};
#endif //_XCACHE_QUIC_H_
