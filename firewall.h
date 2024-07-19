#ifndef FIREWALL_H
#define FIREWALL_H

#include <iostream>
#include <vector>
#include <string>
#include <sqlite3.h>

class Firewall {
public:
    std::vector<std::string> blocked_sites;
    sqlite3 *db;

    Firewall(const std::string& db_path);
    ~Firewall();

    void add_blocked_site(const std::string& site);
    void remove_blocked_site(const std::string& site);
    void get_blocked_sites();
};

#endif // FIREWALL_H
