#include "xiapushserver.hpp"

#include "localconfig.hpp"
// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"

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
#define CONTROL_IP "172.64.0.31"

#define XCACHE_AID "XCACHE_AID"
#define TEST_CID "TEST_CID"

int picoquic_xia_server(LocalConfig conf) {
	int retval = -1;
	int state = 0;
	auto xcache_aid = conf.get(XCACHE_AID); // this need not be xcache so we should pass it indvidually 
    auto test_cid = conf.get(TEST_CID);
	FILE* logfile = NULL;
	XcacheQUICServer server(xcache_aid);
	uint64_t current_time;


    current_time = picoquic_current_time();

	GraphPtr dummy_cid_addr = server.serveCID(test_cid); // This cid will still be served for now 

	state = 2;

	// Open a log file
	logfile = fopen("server.log", "w");
	if(logfile == NULL) {
		printf("ERROR creating log file\n");
		//goto server_done;
	}
	state = 3;
	//PICOQUIC_SET_LOG(server.s, logfile); Create a new function extract

	// Wait for packets

	int64_t delay_max = 10000000;      // max wait 10 sec.
    int64_t delta_t;
	while(1) {
		int64_t delta_t = server.nextWakeDelay(delay_max);

		printf("Going into select\n");

		server.incomingPacket();

		
	}
	// Server ended cleanly, change return code to success
	retval = 0;
	/* // we should do something abt this for quic_server as well
	server_done:
		switch(state) {
			case 3: // close the log file
				fclose(logfile);
			case 2: // cleanup QUIC instance
				picoquic_free(server);
			case 1: // cleanup server sockets
			/*
				if(myaddr.sockfd != -1) {
					close(myaddr.sockfd);
				}
				
		};*/
	return retval;
}