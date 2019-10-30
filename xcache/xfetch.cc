#include "localconfig.hpp"

//#include <string>
#include <memory>
#include <atomic>
#include <iostream>

#include <signal.h>
#include <getopt.h>

#include "quicxiasock.hpp"          // QUICXIASocket
#include "dagaddr.hpp"              // Graph
#include "xcache_quic_client.h"     // XcacheQUICClient
#include "fd_manager.h"             // FdManager

#include "apihandler.h"
#include "chunkapi.h"

#define CONFFILE "xcacheclient.local.conf"
#define CLIENT_AID "CLIENT_AID"
#define SERVER_DAG "THEIR_ADDRESS"

#define TEST_CHUNK_SIZE 8192

using namespace std;

string manifest;
string dag;

auto conf = LocalConfig::get_instance(CONFFILE);
auto client_aid = conf.get(CLIENT_AID);
auto server_dag = conf.get(SERVER_DAG);


// Cleanup on interrupt
atomic<bool> stop(false);

void help()
{
	printf("usage: xfetch [-m manifest] [-d dag]]\n");
	printf("where:\n");
	printf("  -m manifest : fetch chunks listed in the manifest file\n");
	printf("  -d dag      : fetch the chunk specified by dag\n");
	printf("  -h          : display this help\n");
	exit(1);
}


int config(int argc, char **argv)
{
    int opt;
	while ((opt = getopt(argc, argv, "hm:d:")) != -1) {
		switch (opt) {
		case 'h':
			help();
			break;
		case 'm':
			manifest = optarg;
			break;
		case 'd':
			printf("the dag = %s\n\n", optarg);
			dag = optarg;
			break;
		default:
			help();
			break;
		}
	}

	if (manifest.empty() && dag.empty()) {
		// nothing specified
		help();
	}

	// Get XIDs from local config file
//	conf = LocalConfig::get_instance(CONFFILE);
//	client_aid = conf.get(CLIENT_AID);
//	server_dag = conf.get(THEIR_ADDRESS);

}

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

int fetch(int client_sockfd, string dag)
{
	cout << "Fetching " << dag;

	XcacheQUICClient client;

	// Wait for packets
	int64_t delay_max = 10000000;      // max wait 10 sec.
	int64_t delta_t;

	FdManager fd_mgr;
    fd_mgr.addDescriptor(client_sockfd);

	while (true) {
		delta_t = client.nextWakeDelay(delay_max);
		vector<int> ready_fds;
		int ret = fd_mgr.waitForData(delta_t, ready_fds);

		if (stop.load()) {
			cout << "Interrupted. Cleaning up...";
			break;
		}

		if (ret < 0) {      // error
			cout << "ERROR polling for data";
		}
		if (ret == 0) {     // timed out
			continue;
		}

		for (auto fd : ready_fds) {
			if (fd == client_sockfd) {
				client.incomingPacket(client_sockfd);
			} else {
				cout << "unknown socket!";
			}
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	int rc;

	installSIGINTHandler();
	config(argc, argv);

	auto client_socket = make_unique<QUICXIASocket>(client_aid);
	int client_sockfd = client_socket->fd();

	// FIXME: migrate master loop and run this from inside it too
	api_thread_create(client_sockfd);

	if (!manifest.empty()) {
		cid_list_t cids = load_manifest(manifest);
		for (std::vector<std::string>::iterator it = cids.begin(); it != cids.end(); it++) {
			fetch(client_sockfd, *it);
		}
	} else if (!dag.empty()) {
		fetch(client_sockfd, dag);
	} else {
		help();
	}


	return 0;
}
