// High‑performance TCP connect port scanner for AegisScan
//
// Exposed to Python via pybind11 as `aegis_native.port_scan`.
//
// Python usage (after building the extension):
//
//     from aegis_native import port_scan
//     results = port_scan.scan("127.0.0.1", [21, 22, 80, 443], timeout=2.0)
//     # results: list of dicts: {"port": 80, "status": "open" | "closed"}
//
// This implementation focuses on fast TCP connect checks. Banner grabbing
// and service detection are still done in Python, so the C++ part only
// reports which ports are open.

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <vector>
#include <string>
#include <chrono>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace py = pybind11;

namespace {

// Set socket to non‑blocking mode
bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return false;
    }
    return true;
}

// Try to connect to host:port with a timeout (seconds).
// Returns true if connection succeeds, false otherwise.
bool connect_with_timeout(const std::string &host, int port, double timeout_sec) {
    struct addrinfo hints {};
    struct addrinfo *res = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string service = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (rc != 0) {
        return false;
    }

    bool success = false;

    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (!set_nonblocking(sockfd)) {
            close(sockfd);
            continue;
        }

        int conn_rc = ::connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (conn_rc == 0) {
            // Connected immediately
            success = true;
            close(sockfd);
            break;
        } else if (conn_rc == -1 && errno == EINPROGRESS) {
            // Need to wait for connection with select()
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sockfd, &writefds);

            struct timeval tv;
            tv.tv_sec = static_cast<long>(timeout_sec);
            tv.tv_usec = static_cast<long>((timeout_sec - tv.tv_sec) * 1e6);

            int sel_rc = select(sockfd + 1, nullptr, &writefds, nullptr, &tv);
            if (sel_rc > 0 && FD_ISSET(sockfd, &writefds)) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0) {
                    success = true;
                    close(sockfd);
                    break;
                }
            }
        }

        close(sockfd);
    }

    freeaddrinfo(res);
    return success;
}

// C++ implementation of port scan:
// Returns list[dict], each {"port": int, "status": "open" or "closed"}
std::vector<py::dict> scan_ports(
    const std::string &host,
    const std::vector<int> &ports,
    double timeout_sec
) {
    std::vector<py::dict> results;
    results.reserve(ports.size());

    for (int port : ports) {
        py::dict item;
        item["port"] = port;
        bool open = connect_with_timeout(host, port, timeout_sec);
        item["status"] = open ? "open" : "closed";
        results.push_back(std::move(item));
    }

    return results;
}

}  // namespace

PYBIND11_MODULE(port_scan, m) {
    m.doc() = "C++ accelerated TCP connect port scanner for AegisScan";

    m.def(
        "scan",
        &scan_ports,
        py::arg("host"),
        py::arg("ports"),
        py::arg("timeout") = 2.0,
        R"pbdoc(
Scan a list of TCP ports on a host.

Args:
    host (str): Target hostname or IP.
    ports (List[int]): List of ports to scan.
    timeout (float): Connection timeout in seconds for each port.

Returns:
    List[Dict]: Each dict has:
        - port (int)
        - status (str): "open" or "closed"
)pbdoc"
    );
}


