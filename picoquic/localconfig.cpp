#include "localconfig.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

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
		if (line[0] == '#' || line.empty()) {
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
