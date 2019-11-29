
#include "localconfig.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <string.h>

// C Headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>

#include "configmessage.pb.h"

// XIA support
#include "xiaapi.hpp"
#include "dagaddr.hpp"
static std::string& ltrim(std::string& str, const std::string& chars= " \t\r")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}
 
static std::string& rtrim(std::string& str, const std::string& chars= " \t\r")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}
 
static std::string& trim(std::string& str, const std::string& chars= " \t\r")
{
    return ltrim(rtrim(str, chars), chars);
}

LocalConfig& LocalConfig::get_instance(const std::string& confFile)
{
	static LocalConfig config(confFile);
	return config;
}

LocalConfig::LocalConfig(const std::string& confFile)
{
	std::ifstream configuration(confFile);
	if(!configuration.is_open()) {
		throw "ERROR reading local config";
	}
	std::string line;
	while(std::getline(configuration, line)) {
		ltrim(line);
		if (line[0] == '#') {
			continue;
		}
		std::stringstream ss(line);
		std::string item;
		std::vector<std::string> entries;
		while(std::getline(ss, item, '=')) {
			entries.push_back(item);
		}
		if(entries.size() != 2) {
			throw "ERROR in config file";
		}
		_conf[trim(entries[0])] = trim(entries[1]);
	}
	configuration.close();
}

LocalConfig::LocalConfig(){;}

std::string LocalConfig::get(const std::string& param)
{
	auto it = _conf.find(param);
	if (it == _conf.end()) {
		return "";
	}
	return _conf[param];
}

void LocalConfig::stripInputLine(std::string& line)
{
	auto rm_whitespace = [](char ch) {
		return std::isspace<char>(ch, std::locale::classic());
	};

	line.erase(std::remove_if(line.begin(), line.end(), rm_whitespace),
			line.end());
}

int LocalConfig::configure(std::string control_port, std::string control_addr, 
            addr_info_t &raddr, addr_info_t &saddr)
{
   
 std::cout<<"Got "<<control_addr<<" : ";
 std::cout<<control_port<<std::endl;
 struct addrinfo hints, *res, *rp;
 int sock_fd;
 struct sockaddr_in addr;

  /* Create a socket file descriptor */
  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	printf("Failed to open listen socket\n");
	return -1;
  }

  int opt_value = 1;

  /* Eliminates "Address already in use" error from bind. */
  if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				 (const void *)&opt_value , sizeof(int)) < 0) {
	printf("open_listen_socket: Failed to set \
    SO_REUSEADDR socket option\n");
	return -1;
  }

  bzero((char *)&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(control_addr.c_str());
  addr.sin_port = htons(std::stoi(control_port.c_str()));

  if (bind(sock_fd, (struct sockaddr *)&addr,
		   sizeof(addr)) < 0) {
  	perror("\n");
	return -1;
  }

 this->control_socket = sock_fd;

 if(listen(sock_fd, 1) < 0)
 {
 	printf("Failed while listening");
 	return -1;
 }

 this->router_addr = &raddr;
 this->server_addr = &saddr;

 void *ret = config_controller();
 if(!ret)
   return -1;

 return 0;
}

void *LocalConfig::config_controller()
{
	std::cout<<"In config controller"<<std::endl;
	struct sockaddr_storage their_addr;
	socklen_t addr_size = sizeof(struct sockaddr);
	int new_fd;
	char buf[512];
	bzero(buf, 512);
	new_fd = accept(this->control_socket, (struct sockaddr *)&their_addr, 
		&addr_size);
	if(new_fd < 0)
	{
	   		switch(errno)
 		{
 			case EAGAIN : std::cout<<"EAGAIN"<<std::endl; exit(1);
 			case EBADF : std::cout<<"EBADF"<<std::endl; exit(1);
 			case ECONNREFUSED : std::cout<<"ECONNREFUSED"<<std::endl; exit(1);
  			case EFAULT : std::cout<<"EFAULT"<<std::endl; exit(1);
  			case EINTR : std::cout<<"EINTR"<<std::endl; exit(1);
   			case EINVAL : std::cout<<"EINVAL"<<std::endl; exit(1);
   			default : std::cout<<"new fd Something else"<<std::endl; exit(1);
 		}

	}
	int bytes_recvd = recv(new_fd, buf, 512, 0);
	if(bytes_recvd < 0)
 	{
 		switch(errno)
 		{
 			case EAGAIN : std::cout<<"EAGAIN"<<std::endl; exit(1);
 			case EBADF : std::cout<<"EBADF"<<std::endl; exit(1);
 			case ECONNREFUSED : std::cout<<"ECONNREFUSED"<<std::endl; exit(1);
  			case EFAULT : std::cout<<"EFAULT"<<std::endl; exit(1);
  			case EINTR : std::cout<<"EINTR"<<std::endl; exit(1);
   			case EINVAL : std::cout<<"EINVAL"<<std::endl; exit(1);
   			case ENOMEM : std::cout<<"ENOMEM"<<std::endl; exit(1);
     		        case ENOTCONN : std::cout<<"ENOTCONN"<<std::endl; exit(1);
   			case ENOTSOCK : std::cout<<"ENOTSOCK"<<std::endl; exit(1);		       
   			default : std::cout<<"Something else "<<bytes_recvd<<std::endl; exit(1);
 		}
 		printf("Recv failed\n");
 		return NULL;
 	}
 	std::string s;
	int i=4;
 	while(i<bytes_recvd)
 		s.push_back(buf[i++]);
 	std::cout<<"Length is "<<s.length()<<std::endl;
 	configmessage::Config myconfig;
 	myconfig.ParseFromString(s);
 	set_config(myconfig);


 	this->serverdag_str = myconfig.serverdag();
	std::cout<<"serverdag is "<<myconfig.serverdag()<<" len: "<<myconfig.serverdag().length()<<std::endl;
	server_addr->dag.reset(new Graph(myconfig.serverdag()));
	server_addr->dag->fill_sockaddr(&server_addr->addr);

 	router_addr->sockfd = picoquic_xia_open_server_socket(this->aid.c_str(), router_addr->dag,
 		this->_iface, *this);
 	if(router_addr->sockfd < 0)
 		return NULL;
 	router_addr->dag->fill_sockaddr(&router_addr->addr);
 	router_addr->addrlen = sizeof(sockaddr_x);

 	return (void *)1;
}

void LocalConfig::set_config(configmessage::Config myconfig)
{
	this->_name = myconfig.name();
	this->aid = myconfig.aid();
	this->_r_addr = myconfig.ipaddr();
	this->_iface = myconfig.iface();
	this->_r_port = myconfig.port();
	this->_r_ad = myconfig.ad();
	this->_r_hid = myconfig.hid();
	this->serverdag_str = myconfig.serverdag();
}

std::string LocalConfig::get_raddr()
{
	return this->_r_addr;
}

std::string LocalConfig::get_rport()
{
	return this->_r_port;
}

std::string LocalConfig::get_our_addr()
{
	return "RE " + this->_r_ad + " " + this->_r_hid;
}

std::string LocalConfig::get_their_addr()
{
	return "";
}

std::string LocalConfig::get_server_aid()
{
	return "";
}

std::string LocalConfig::get_router_iface()
{
	return this->_iface;
}

std::string LocalConfig::get_ticket_store()
{
	return "";
}

std::string LocalConfig::get_serverdag_str()
{
	return this->serverdag_str;
}
