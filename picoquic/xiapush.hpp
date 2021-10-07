#ifndef PICOQUIC_XIAPUSHGET_H
#define PICOQUIC_XIAPUSHGET_H

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

class LocalConfig;

/** picoquic_xia_push gets the client and server address. 
 * It creates a connection to the server and sends some dummy data 
 * This return 1 if there is an error and 0 if not 
 * */
int picoquic_xia_push_client(picoquic_quic_t *client) {
}

