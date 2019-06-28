#ifndef XIA_LOCAL_CONFIG_H
#define XIA_LOCAL_CONFIG_H

#include <string>
#include <unordered_map>

// Read in a local.conf file containing addresses for a local QUIC instance
// We can probably auto-generate the conf file from XIAConfigurator
class LocalConfig {
    public:
		static LocalConfig& get_instance(const std::string& confFile);
        std::string get(const std::string& param);
    private:
        LocalConfig(const std::string& confFile);
		void stripInputLine(std::string& line);
        std::unordered_map<std::string, std::string> _conf;
};

#endif //XIA_LOCAL_CONFIG_H
