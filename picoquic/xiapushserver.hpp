#ifndef PICOQUIC_XIAPUSHSERVER_H
#define PICOQUIC_XIAPUSHSERVER_H

#include "localconfig.hpp"
#include "xcache_quic_server.h"
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

/** picoquic_xia_push gets the client and server address. 
 * It creates a connection to the server and sends some dummy data 
 * This return 1 if there is an error and 0 if not 
 * */

#define TABLE_SIZE 5000009

int picoquic_xia_push_server(std::string xcache_aid, std::string test_cid);

#endif
