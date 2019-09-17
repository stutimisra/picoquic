#include "localconfig.hpp"

#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

extern "C" {
#include "picoquic.h"
#include "picosocks.h"
#include "util.h"
};
#include "quicxiasock.hpp"
#include "xiaapi.hpp"
#include "dagaddr.hpp"
#include "cid_header.h"
#include "xcache_quic_server.h"
#include "fd_manager.h"

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "xcache.local.conf"
#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"

#define TEST_CHUNK_SIZE 8192

using namespace std;

// Cleanup on interrupt
atomic<bool> stop(false);

// Simply flip the 'stop' switch so main loop will exit and clean up
void sigint_handler(int) {
	stop.store(true);
}

void installSIGINTHandler() {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = sigint_handler;
	sigfillset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
}

int main()
{
	int retval = -1;

	installSIGINTHandler();

	// Get XIDs from local config file
	auto conf = LocalConfig::get_instance(CONFFILE);
	auto xcache_aid = conf.get(XCACHE_AID);
	auto test_cid = conf.get(TEST_CID);
	if (xcache_aid.size() == 0) {
		printf("ERROR: XCACHE_AID entry missing in %s\n", CONFFILE);
		return -1;
	}
	if (test_cid.size() == 0) {
		printf("ERROR: TEST_CID entry missing in %s\n", CONFFILE);
		return -1;
	}
	
	// We give a fictitious AID for now, and get a dag in my_addr
	auto xcache_socket = make_unique<QUICXIASocket>(xcache_aid);
	GraphPtr dummy_cid_addr = xcache_socket->serveCID(test_cid);
	int xcache_sockfd = xcache_socket->fd();

	XcacheQUICServer server;

	// Wait for packets
	int64_t delay_max = 10000000;      // max wait 10 sec.
	int64_t delta_t;

	FdManager fd_mgr;
	fd_mgr.addDescriptor(xcache_sockfd);

	while (true) {
		delta_t = server.nextWakeDelay(delay_max);
		std::vector<int> ready_fds;
		int ret = fd_mgr.waitForData(delta_t, ready_fds);
		if (ret < 0) {
			std::cout << "ERROR polling for data" << endl;
		}
		if (ret == 0) {
			// timed out
			continue;
		}

		for (auto fd : ready_fds) {
			if (fd == xcache_sockfd) {
				server.incomingPacket(xcache_sockfd);
			}
		}

		if (stop.load()) {
			std::cout << "Interrupted. Cleaning up." << std::endl;
			break;
		}
	}

	// Server ended cleanly, change return code to success
	retval = 0;

server_done:
	return retval;
}
