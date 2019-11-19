#ifndef XIA_LOCAL_CONFIG_H
#define XIA_LOCAL_CONFIG_H

#include <string>
#include <unordered_map>
#include <pthread.h>

// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"

typedef struct addr_info_t {
	int sockfd;
	GraphPtr dag;
	sockaddr_x addr;
	int addrlen;
};

// Read in a local.conf file containing addresses for a local QUIC instance
// We can probably auto-generate the conf file from XIAConfigurator
class LocalConfig {
    public:
    	LocalConfig();
		static LocalConfig& get_instance(const std::string& confFile);
        std::string get(const std::string& param);
        int configure(std::string control_port, std::string control_addr, addr_info_t &addr);
		void *config_controller();
		std::string get_raddr();
		std::string get_rport();
		std::string get_our_addr();
		std::string get_their_addr();
		std::string get_server_aid();
		std::string get_router_iface();
		std::string get_ticket_store();
    private:
        LocalConfig(const std::string& confFile);
		void stripInputLine(std::string& line);
        std::unordered_map<std::string, std::string> _conf;
        int control_socket;
        pthread_t control_thread;
        GraphPtr mydag;
        sockaddr_x *saddr;
};

#endif //XIA_LOCAL_CONFIG_H
