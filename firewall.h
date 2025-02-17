#ifndef FIREWALL_H
#define FIREWALL_H

#include <iostream>
#include <vector>
#include <string>
#include <sqlite3.h>
#include <pcap.h>
#include <unordered_map>
using namespace std;

class Firewall {
public:
    std::vector<std::string> blocked_sites;
    std::vector<int> blocked_protocols;
    unordered_map<int,int> map;
    sqlite3 *db;

    Firewall(const std::string& db_path);
    ~Firewall();
    bool search_if_blocked(const std::string& packet_data);
    void add_blocked_site(const std::string& site);
    void remove_blocked_site(const std::string& site);
    void get_blocked_sites();
    void add_blocked_protocol(int protocol);
    void add_blocked_range(int start,int end);
    void remove_blocked_range(int start,int end);
    bool is_ip_blocked_in_range(int ip);
    void get_blocked_range();
    void remove_blocked_protocol(int protocol);
    void get_blocked_protocols();
    void start_packet_capture(const std::string& interface);
    bool is_packet_blocked(const std::string& packet_data);
    bool is_protocol_blocked(int protocol);
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // FIREWALL_H
