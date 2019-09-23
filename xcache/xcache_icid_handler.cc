#include "xcache_icid_handler.h"

#include <sys/types.h>      // bind
#include <sys/socket.h>     // bind

XcacheICIDHandler::XcacheICIDHandler(XcacheQUICServer& server)
    : _server(server) {

    // Create a socket that we'll accept incoming ICID requests on
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        throw "ERROR: Unable to create socket for ICID Handler";
    }

    // Bind to ICID Handler Port
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ICID_HANDLER_PORT);
    addr.sin_addr.s_addr = htons(INADDR_ANY);
    if (bind(_sockfd, (struct sockaddr*)&addr, sizeof(addr))){
        throw "ERROR: binding to ICID Handler port";
    }

    _sockfd = sockfd;
}

int XcacheICIDHandler::fd() {
    return _sockfd;
}

int XcacheICIDHandler::handleICIDRequest() {
    // TODO: ICID packet parsing and action here
    return 0;
}
