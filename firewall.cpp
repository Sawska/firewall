#include "firewall.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>

Firewall::Firewall(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    std::string create_sites_table = 
        "CREATE TABLE IF NOT EXISTS blocked_sites (id INTEGER PRIMARY KEY, site TEXT UNIQUE);";
    if (sqlite3_exec(db, create_sites_table.c_str(), 0, 0, 0) != SQLITE_OK) {
        std::cerr << "Can't create table: " << sqlite3_errmsg(db) << std::endl;
    }

    std::string create_protocols_table = 
        "CREATE TABLE IF NOT EXISTS blocked_protocols (id INTEGER PRIMARY KEY, protocol INTEGER UNIQUE);";
    if (sqlite3_exec(db, create_protocols_table.c_str(), 0, 0, 0) != SQLITE_OK) {
        std::cerr << "Can't create protocols table: " << sqlite3_errmsg(db) << std::endl;
    }
     std::string create_range_table = 
        "CREATE TABLE IF NOT EXISTS blocked_ip_ranges (id INTEGER PRIMARY KEY, range_start INTEGER NOT NULL, range_end INTEGER NOT NULL);";
    if (sqlite3_exec(db, create_range_table.c_str(), 0, 0, 0) != SQLITE_OK) {
        std::cerr << "Can't create blocked_ip_ranges table: " << sqlite3_errmsg(db) << std::endl;
    }


    get_blocked_sites();
    get_blocked_protocols();
    get_blocked_range();
}

Firewall::~Firewall() {
    if (db) {
        sqlite3_close(db);
    }
}

bool Firewall::search_if_blocked(const std::string &packet_data) {
    for (const std::string& site : blocked_sites) {
        if (packet_data == site) {
            return true;
        }
    }
    return false;
}

void Firewall::add_blocked_site(const std::string& site) {
    std::string sql = "INSERT INTO blocked_sites (site) VALUES (?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't insert site: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_sites();
}

void Firewall::remove_blocked_site(const std::string& site) {
    std::string sql = "DELETE FROM blocked_sites WHERE site = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't delete site: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_sites();
}

void Firewall::get_blocked_sites() {
    blocked_sites.clear();

    std::string sql = "SELECT site FROM blocked_sites;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            blocked_sites.push_back(std::string(reinterpret_cast<const char*>(text)));
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }
}

void Firewall::add_blocked_protocol(int protocol) {
    std::string sql = "INSERT INTO blocked_protocols (protocol) VALUES (?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, protocol);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't insert protocol: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_protocols();
}

void Firewall::add_blocked_range(int start, int end) {
    std::string sql = "INSERT INTO blocked_ip_ranges (range_start, range_end) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, start);
        sqlite3_bind_int(stmt, 2, end);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't insert IP range: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_range();
}

void Firewall::remove_blocked_range(int start, int end) {
    std::string sql = "DELETE FROM blocked_ip_ranges WHERE range_start = ? AND range_end = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, start);
        sqlite3_bind_int(stmt, 2, end);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't delete IP range: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_range();
}

bool Firewall::is_ip_blocked_in_range(int ip) {
    for (const auto& entry : map) {
        int range_start = entry.first;
        int range_end = entry.second;
        if (ip >= range_start && ip <= range_end) {
            return true;
        }
    }
    return false;
}


void Firewall::get_blocked_range() {
    map.clear();
    std::string sql = "SELECT range_start, range_end FROM blocked_ip_ranges;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int start = sqlite3_column_int(stmt, 0);
            int end = sqlite3_column_int(stmt, 1);
            map[start] = end;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }
}

void Firewall::remove_blocked_protocol(int protocol)
{
    std::string sql = "DELETE FROM blocked_protocols WHERE protocol = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, protocol);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Can't delete protocol: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }

    get_blocked_protocols();
}

void Firewall::get_blocked_protocols() {
    blocked_protocols.clear();

    std::string sql = "SELECT protocol FROM blocked_protocols;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int protocol = sqlite3_column_int(stmt, 0);
            blocked_protocols.push_back(protocol);
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Can't prepare statement: " << sqlite3_errmsg(db) << std::endl;
    }
}

void Firewall::start_packet_capture(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << interface << ": " << errbuf << std::endl;
        return;
    }
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
    pcap_close(handle);
}

void Firewall::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    Firewall* firewall = reinterpret_cast<Firewall*>(userData);
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + 14); // Ethernet header is typically 14 bytes

    if (firewall->is_protocol_blocked(ipHeader->ip_p)) {
        std::cout << "Blocked packet with protocol " << static_cast<int>(ipHeader->ip_p) << std::endl;
        return;
    }

    char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    std::string srcIPStr(srcIP);
    std::string destIPStr(destIP);

    struct in_addr destAddr;
    inet_pton(AF_INET, destIPStr.c_str(), &destAddr);

    if (firewall->is_ip_blocked_in_range(ntohl(destAddr.s_addr))) {
        std::cout << "Blocked packet from " << srcIPStr << " to " << destIPStr << std::endl;
        return;
    }

    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ipHeader->ip_hl * 4));
        if (firewall->is_packet_blocked(destIPStr)) {
            std::cout << "Blocked TCP packet from " << srcIPStr << " to " << destIPStr << std::endl;
        } else {
            std::cout << "Allowed TCP packet from " << srcIPStr << " to " << destIPStr << std::endl;
        }
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(packet + 14 + (ipHeader->ip_hl * 4));
        if (firewall->is_packet_blocked(destIPStr)) {
            std::cout << "Blocked UDP packet from " << srcIPStr << " to " << destIPStr << std::endl;
        } else {
            std::cout << "Allowed UDP packet from " << srcIPStr << " to " << destIPStr << std::endl;
        }
    }
}


bool Firewall::is_protocol_blocked(int protocol) {
    for (int blocked_protocol : blocked_protocols) {
        if (protocol == blocked_protocol) {
            return true;
        }
    }
    return false;
}

bool Firewall::is_packet_blocked(const std::string& packet_data) {
    return search_if_blocked(packet_data);
}
