#ifndef _XCACHE_ICID_HANDLER_H
#define _XCACHE_ICID_HANDLER_H

#include "xcache_quic_server.h"

#define ICID_HANDLER_PORT 7934

class XcacheICIDHandler {
public:
    XcacheICIDHandler(XcacheQUICServer& server);
    int fd();
    int handleICIDRequest();
private:
    XcacheQUICServer& _server;
    int _sockfd;
};
#endif //_XCACHE_ICID_HANDLER_H
