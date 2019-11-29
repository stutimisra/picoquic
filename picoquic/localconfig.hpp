#ifndef XIA_LOCAL_CONFIG_H
#define XIA_LOCAL_CONFIG_H

#include <string>
#include <unordered_map>
#include <pthread.h>

// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"

#include "configmessage.pb.h"

struct addr_info_t {
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
        int configure(std::string control_port, std::string control_addr, 
            addr_info_t &raddr, addr_info_t &saddr);
		void *config_controller();
		std::string get_raddr();
		std::string get_rport();
        std::string get_serverdag_str();
		std::string get_our_addr();
		std::string get_their_addr();
		std::string get_server_aid();
		std::string get_router_iface();
		std::string get_ticket_store();
        std::string control_addr;
        std::string control_port;
    private:
        LocalConfig(const std::string& confFile);
		void stripInputLine(std::string& line);
		void set_config(configmessage::Config myconfig);
        std::unordered_map<std::string, std::string> _conf;
        int control_socket;
        pthread_t control_thread;
        std::string aid;
        addr_info_t *router_addr;
        addr_info_t *server_addr;
        std::string _name;
        // my interface with the router
        std::string _iface;
        // router's IP address
        std::string _r_addr;
        // router's Port
        std::string _r_port;
        // router's AD
        std::string _r_ad;
        // router's HID
        std::string _r_hid;
        // server dagstr
        std::string serverdag_str;
};

#endif //XIA_LOCAL_CONFIG_H
