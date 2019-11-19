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

int LocalConfig::configure(std:: string control_port, std::string control_addr, addr_info_t &addr)
{
   
 std::cout<<"Got "<<control_addr<<" : ";
 std::cout<<control_port<<std::endl;
 struct addrinfo hints, *res, *rp;
 int sock_fd;

 struct sockaddr_in saddr;

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

  bzero((char *)&saddr, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr(control_addr.c_str());
  saddr.sin_port = htons(std::stoi(control_port.c_str()));

  if (bind(sock_fd, (struct sockaddr *)&saddr,
		   sizeof(saddr)) < 0) {

	switch(errno)
	{
		case EACCES : std::cout<<"Access"; exit(1);
		case EADDRINUSE: std::cout<<"Address in use "; exit(1);
		case EBADF : std::cout<<"Bad socket"; exit(1);
		case EINVAL : std::cout<<"already bound"; exit(1);
		case EADDRNOTAVAIL: std::cout<<"interface not local"; exit(1);
		case EFAULT: std::cout<<"EFAULT"; exit(1);
		default : std::cout<<"something else"; exit(1);
	}
	printf("open_listen_socket: Failed to bind \
    listening socket to port %s\n", control_port);
	return -1;
  }

 this->control_socket = sock_fd;

 if(listen(sock_fd, 1) < 0)
 {
 	printf("Failed while listening");
 	return -1;
 }

 std::cout<<"Bound"<<std::endl;
 //freeaddrinfo(res);
 //std::cout<<"freeaddrinfo"<<std::endl;

 // if(pthread_create(&control_thread, NULL, config_controller, NULL) < 0)
 // {
 // 	printf("Failed to create a thread\n");
 // 	return -1;
 // }
 // 
 config_controller();

 return 0;
}

void *LocalConfig::config_controller()
{
	std::cout<<"In config controller"<<std::endl;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	int new_fd;
	char buf[512];
	new_fd = accept(this->control_socket, (struct sockaddr *)&their_addr, 
		&addr_size);
	if(recv(new_fd, buf, 512, 0) < 0)
 	{
 		printf("Recv failed\n");
 		return (void *)-1;
 	}
 	printf("Recvd %s", buf);
 	std::string s = buf;
 	configmessage::Config myconfig;
 	myconfig.ParseFromString(s);
 	return NULL;

 	exit(0);
}

std::string LocalConfig::get_raddr()
{
	return "";
}

std::string LocalConfig::get_rport()
{
	return "";
}

std::string LocalConfig::get_our_addr()
{
	return "";
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
	return "";
}

std::string LocalConfig::get_ticket_store()
{
	return "";
}

