#ifndef _XCACHE_QUIC_CLIENT_H
#define _XCACHE_QUIC_CLIENT_H

#include <vector>
#include <memory>

extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};

// XIA Includes
#include "publisher/publisher.h"
#include "headers/content_header.h"


#include "xcache_quic.h"

#include "xiaapi.hpp"

using namespace std;

#define TEST_CHUNK_SIZE 8192

using XcacheQUICPtr = std::unique_ptr<XcacheQUIC>;

//enum class ChunkState {INITIAL, FETCHING_HEADER, FETCHING_DATA, READY};

//struct chunk {
//	ChunkState state = ChunkState::INITIAL;
//	int hdr_len = -1;
//	std::vector<uint8_t> buf;
//	std::unique_ptr<ContentHeader> chdr;
//	std::unique_ptr<uint8_t> data;
//};

//typedef struct {
//	int stream_open;
//	int received_so_far;
//	std::vector<uint8_t> data;
//	size_t datalen;
//	size_t recv_offset;		// FIXME: do i need this??
//	size_t sent_offset;		// FIXME: do i need this??
//	NodePtr xid;
//
//	// added from client code
//	uint64_t last_interaction_time;
//	std::unique_ptr<struct chunk> chunk;
//} callback_context_t;

class XcacheQUICClient {
	public:
		XcacheQUICClient();
		int64_t nextWakeDelay(int64_t delay_max);
		void updateTime();
		int incomingPacket(int sockfd);
	private:
		static int client_callback(picoquic_cnx_t* connection,
				uint64_t stream_id, uint8_t* bytes, size_t length,
				picoquic_call_back_event_t event, void* ctx);
		void print_address(struct sockaddr* address, char* label);
//		static int buildDataToSend(callback_context_t* ctx, size_t datalen);
		static int sendData(picoquic_cnx_t* connection,
				uint64_t stream_id, callback_context_t* ctx);
		static int remove_context(picoquic_cnx_t* connection,
				callback_context_t* context);
		static int process_data(callback_context_t* context,
				uint8_t* bytes, size_t length);

		string fetch(string dag);


		// ADDED FROM CLIENT
		static int receive_data(callback_context_t* context,
			uint8_t* bytes, size_t length);
		static void start_stream(picoquic_cnx_t* connection,
			callback_context_t* context);
		// still needed???
		//static int end_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
		//	callback_context_t* context);
		// DONE ADDED SECTION

		XcacheQUIC quic;
		int bytes_recv;                    // size of packet received
		size_t send_length = 0;
		unsigned char received_ecn;
		picoquic_cnx_t* newest_cnx = NULL;
		picoquic_cnx_t* next_connection = NULL;
		uint8_t buffer[1536];              // buffer to receive packets
		uint8_t send_buffer[1536];
		int64_t delay_max = 10000000;      // max wait 10 sec.
		unsigned long to_interface = 0;    // our interface
		sockaddr_x addr_from;
		sockaddr_x addr_local;
		int64_t delta_t;

};
#endif //_XCACHE_QUIC_CLIENT_H
