#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <signal.h>

#include "quicxiasock.hpp"          // QUICXIASocket
#include "dagaddr.hpp"              // Graph
#include "xcache_quic_server.h"     // XcacheQUICServer
#include "xcache_quic_client.h"     // XcacheQUICClient
#include "xcache_icid_handler.h"    // XcacheICIDHandler
#include "fd_manager.h"             // FdManager


#include "apihandler.h"
#include "chunkapi.h"



#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#define CONFFILE "xcache.local.conf"
#define XCACHE_AID "XCACHE_AID"
#define CLIENT_AID "CLIENT_AID"
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
	installSIGINTHandler();

	// Get XIDs from local config file
	auto conf = LocalConfig::get_instance(CONFFILE);
	auto xcache_aid = conf.get(XCACHE_AID);
	auto client_aid = conf.get(CLIENT_AID);
	auto test_cid = conf.get(TEST_CID);
	if (xcache_aid.size() == 0) {
		cout << "ERROR: XCACHE_AID entry missing in " << CONFFILE << endl;
		return -1;
	}
	if (test_cid.size() == 0) {
		cout << "ERROR: TEST_CID entry missing in " << CONFFILE << endl;
		return -1;
	}

	// We give a fictitious AID for now, and get a dag in my_addr
	auto xcache_socket = make_unique<QUICXIASocket>(xcache_aid);
	GraphPtr dummy_cid_addr = xcache_socket->serveCID(test_cid);
	int xcache_sockfd = xcache_socket->fd();

	auto client_socket = make_unique<QUICXIASocket>(client_aid);
	int client_sockfd = client_socket->fd();


	XcacheQUICServer server;
	XcacheQUICClient client;
    XcacheICIDHandler icid_handler(server);

	// FIXME: integrate into the loop below instead of being a separate thread
	api_thread_create(xcache_sockfd);

	// Wait for packets
	int64_t delay_max = 10000000;      // max wait 10 sec.
	int64_t delta_t;

	FdManager fd_mgr;
	fd_mgr.addDescriptor(xcache_sockfd);
    fd_mgr.addDescriptor(icid_handler.fd());
    fd_mgr.addDescriptor(client_sockfd);

	while (true) {
		delta_t = server.nextWakeDelay(delay_max);
		std::vector<int> ready_fds;
		int ret = fd_mgr.waitForData(delta_t, ready_fds);

		if (stop.load()) {
			std::cout << "Interrupted. Cleaning up..." << std::endl;
			break;
		}

		if (ret < 0) {      // error
			std::cout << "ERROR polling for data" << endl;
		}
		if (ret == 0) {     // timed out
			continue;
		}

		for (auto fd : ready_fds) {
			if (fd == xcache_sockfd) {
				server.incomingPacket(xcache_sockfd);
			}
			if (fd == client_sockfd) {
				client.incomingPacket(client_sockfd);
			}
            if (fd == icid_handler.fd()) {
                // We have an ICID packet to parse
                continue;
            }
		}

	}

	// Server ended. Return success
	return 0;
}
