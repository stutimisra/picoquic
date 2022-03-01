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



int picoquic_xia_server(std::string xcache_aid, std::string test_cid) {
	int retval = -1;
	int state = 0;
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