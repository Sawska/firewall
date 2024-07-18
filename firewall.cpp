#include <iostream>
#include <vector>
#include <string>
#include <sqlite3.h>

class Firewall {
public:
    std::vector<std::string> blocked_sites;
    sqlite3 *db;

    Firewall(const std::string& db_path) {
        if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
            std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
            return;
        }
        // Create table if it doesn't exist
        std::string sql = "CREATE TABLE IF NOT EXISTS blocked_sites (id INTEGER PRIMARY KEY, site TEXT UNIQUE);";
        if (sqlite3_exec(db, sql.c_str(), 0, 0, 0) != SQLITE_OK) {
            std::cerr << "Can't create table: " << sqlite3_errmsg(db) << std::endl;
        }
    }

    ~Firewall() {
        if (db) {
            sqlite3_close(db);
        }
    }

    void add_blocked_site(const std::string& site) {
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

    void remove_blocked_site(const std::string& site) {
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

    void get_blocked_sites() {
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
};

