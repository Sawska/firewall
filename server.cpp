#include <iostream>
#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <sstream>
#include "Firewall.h"  

using boost::asio::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket socket, Firewall& firewall)
        : m_socket(std::move(socket)), m_firewall(firewall) { }

    void run() {
        wait_for_request();
    }

    static std::unordered_map<std::string, std::function<void(session&)>> routes;
private:
    void wait_for_request() {
        auto self(shared_from_this());

        boost::asio::async_read_until(m_socket, m_buffer, "\r\n\r\n",
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                std::istream request_stream(&m_buffer);
                std::string request_line;
                std::getline(request_stream, request_line);

                std::istringstream request_line_stream(request_line);
                std::string method;
                std::string uri;
                std::string http_version;
                request_line_stream >> method >> uri >> http_version;

                std::cout << "Request: " << method << " " << uri << " " << http_version << std::endl;

                if (routes.find(uri) != routes.end()) {
                    routes[uri](*this);
                } else {
                    send_not_found();
                }

                wait_for_request();
            } else {
                std::cout << "Error: " << ec.message() << std::endl;
            }
        });
    }

    void send_not_found() {
        auto self(shared_from_this());
        const std::string not_found_response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 13\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "404 Not Found";
        boost::asio::async_write(m_socket, boost::asio::buffer(not_found_response),
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
            if (ec) {
                std::cout << "Error: " << ec.message() << std::endl;
            }
        });
    }

    tcp::socket m_socket;
    boost::asio::streambuf m_buffer;
    Firewall& m_firewall;
};

std::unordered_map<std::string, std::function<void(session&)>> session::routes;

class server
{
public:
    server(boost::asio::io_context& io_context, short port, Firewall& firewall)
        : m_acceptor(io_context, tcp::endpoint(tcp::v4(), port)), m_firewall(firewall) {
        do_accept();
    }

private:
    void do_accept() {
        m_acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::cout << "Creating session on: "
                          << socket.remote_endpoint().address().to_string()
                          << ":" << socket.remote_endpoint().port() << '\n';
                std::make_shared<session>(std::move(socket), m_firewall)->run();
            } else {
                std::cout << "Error: " << ec.message() << std::endl;
            }

            do_accept();
        });
    }

    tcp::acceptor m_acceptor;
    Firewall& m_firewall;
};

void handle_root(session& sess) {
    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 13\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello, World!";
    boost::asio::async_write(sess.m_socket, boost::asio::buffer(response),
    [&sess](boost::system::error_code ec, std::size_t /*length*/) {
        if (ec) {
            std::cout << "Error: " << ec.message() << std::endl;
        }
    });
}

void add_site(session& sess) {
    // Parse the site to add from the request
    std::istream request_stream(&sess.m_buffer);
    std::string request_line;
    std::getline(request_stream, request_line);  // Skip the request line
    std::string site;
    std::getline(request_stream, site);
    sess.m_firewall.add_blocked_site(site);

    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 16\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Site Added: " + site;
    boost::asio::async_write(sess.m_socket, boost::asio::buffer(response),
    [&sess](boost::system::error_code ec, std::size_t /*length*/) {
        if (ec) {
            std::cout << "Error: " << ec.message() << std::endl;
        }
    });
}

void remove_site(session& sess) {
    // Parse the site to remove from the request
    std::istream request_stream(&sess.m_buffer);
    std::string request_line;
    std::getline(request_stream, request_line);  // Skip the request line
    std::string site;
    std::getline(request_stream, site);
    sess.m_firewall.remove_blocked_site(site);

    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 19\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Site Removed: " + site;
    boost::asio::async_write(sess.m_socket, boost::asio::buffer(response),
    [&sess](boost::system::error_code ec, std::size_t /*length*/) {
        if (ec) {
            std::cout << "Error: " << ec.message() << std::endl;
        }
    });
}

void get_sites(session& sess) {
    sess.m_firewall.get_blocked_sites();
    std::string sites_list;
    for (const auto& site : sess.m_firewall.blocked_sites) {
        sites_list += site + "\n";
    }

    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: " + std::to_string(sites_list.size()) + "\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n" +
        sites_list;
    boost::asio::async_write(sess.m_socket, boost::asio::buffer(response),
    [&sess](boost::system::error_code ec, std::size_t /*length*/) {
        if (ec) {
            std::cout << "Error: " << ec.message() << std::endl;
        }
    });
}

int main() {
    try {
        boost::asio::io_context io_context;
        Firewall firewall("blocked_sites.db");

        session::routes["/"] = handle_root;
        session::routes["/add_site"] = add_site;
        session::routes["/remove_site"] = remove_site;
        session::routes["/get_sites"] = get_sites;

        server s(io_context, 8080, firewall);
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
