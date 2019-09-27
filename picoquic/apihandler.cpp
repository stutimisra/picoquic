#include <thread>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>

#include "xiaapi.hpp"
#include "chunkapi.h"
#include "chunkapi.pb.h"


static bool alive;
static int server_sock;		// only used to get peer info for route table entries


int _update_chunk_metadata(std::string& s)
{
	ChunkAPI::chunk_list list;
	//
	// chunk file should have already been written to disk outside of the app

	list.ParseFromString(s);
	list.PrintDebugString();

	uint32_t ttl = list.ttl();
	uint32_t count = list.cids_size();

	printf("ttl = %u count = %u\n", ttl, count);

	for (uint32_t i = 0; i < count; i++) {
		std::string cid = "CID:" + list.cids(i);

		// add route entry to the XIA router's forwarding table
		printf("cid = %s\n", cid.c_str());
		GraphPtr cid_addr;
		if (picoquic_xia_serve_cid(server_sock, cid.c_str(), cid_addr)) {
			printf("ERROR setting up routes for %s\n", cid.c_str());
			break;
		}
	}

	// FIXME: add logic to create and manage list of chunks that will time out
}


int _api_pull()
{

}

void api_handler(int sockfd)
{
	char *buf, *p;
	int length;
	int rc;

	printf("reading\n");

	// get protobuf data size
	if (read(sockfd, &length, sizeof(length)) != sizeof(length)) {
		// error return
	}
	length = ntohl(length);

	printf("length = %d\n", length);

	// get the data
	if ((buf = (char *)malloc(length)) == NULL) {
		// return error
	}

	p = buf;
	int num = length;
	while (num > 0) {
		printf("reading\n");
		rc = read(sockfd, p, num);

		if (rc < 0) {
			break;
		}

		num -= rc;
		p += rc;
	}

	if (rc >= 0) {
		std::string s(buf, length);
		_update_chunk_metadata(s);

	} else {
		perror("error reading API packet");
	}

	close(sockfd);
}

void api_thread()
{
	int rc;
	struct addrinfo *ai;
	int s = socket(AF_INET, SOCK_STREAM, 0);

	getaddrinfo("localhost", "6666", NULL, &ai);
	rc = bind(s, ai->ai_addr, sizeof(sockaddr_in));
	freeaddrinfo(ai);
	rc = listen(s, 5);

	while (alive) {
		struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(s, &fds);

		int rc = select(s + 1, &fds, NULL, NULL, &tv);
		if (rc > 0) {
			int sockfd = accept(s, NULL, NULL);

			if (sockfd != -1) {
				std::thread(api_handler, sockfd).detach();
			}
		} else if (rc < 0) {
			break;

		} else {
			// FIXME: periodically check for expired chunks and purge them
		}
	}
}


void api_thread_create(int sock)
{
	alive = true;
	server_sock = sock;		// save server sock for use with router API

	std::thread(api_thread).detach();
}


void api_thread_destroy()
{
	alive = false;

	// also delete any chunks with a ttl?
}


