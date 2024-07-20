#ifndef FIREWALL_H
#define FIREWALL_H

#include <iostream>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <boost/algorithm/string.hpp>

class Firewall {
public:
    std::vector<std::string> blocked_sites;
    sqlite3 *db;

    Firewall(const std::string& db_path);
    ~Firewall();

    void add_blocked_site(const std::string& site);
    void remove_blocked_site(const std::string& site);
    void get_blocked_sites();

    std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
        std::vector<std::string> parts;
        boost::algorithm::split(parts, s, boost::algorithm::is_any_of(delimiter));
        return parts;
    }
};

#endif // FIREWALL_H
