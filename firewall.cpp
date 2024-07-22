#include "firewall.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


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
}


Firewall::~Firewall() {
    if (db) {
        sqlite3_close(db);
    }
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
}


void Firewall::remove_blocked_protocol(int protocol) {
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
    const struct ip* ipHeader = (struct ip*)(packet + 14); 

    if (firewall->is_protocol_blocked(ipHeader->ip_p)) {
        std::cout << "Blocked packet with protocol " << static_cast<int>(ipHeader->ip_p) << std::endl;
        return;
    }

    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
        char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

        std::string srcIPStr(srcIP);
        std::string destIPStr(destIP);

        if (firewall->is_packet_blocked(destIPStr)) {
            std::cout << "Blocked packet from " << srcIPStr << " to " << destIPStr << std::endl;
        } else {
            std::cout << "Allowed packet from " << srcIPStr << " to " << destIPStr << std::endl;
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
