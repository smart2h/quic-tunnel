#include "util.h"

#include <cstdio>
#include <cstring>

#include "log.h"

namespace quic_tunnel {

uint8_t udp_buffer[65535];
uint8_t quic_buffer[65500];

const char *ToString(const sockaddr_storage &addr) {
  static char buf[INET_ADDRSTRLEN + 6];
  if (inet_ntop(AF_INET,
                &reinterpret_cast<const sockaddr_in *>(&addr)->sin_addr, buf,
                sizeof(buf))) {
    auto len = strlen(buf);
    snprintf(buf + len, sizeof(buf) - len, ":%d",
             ntohs(reinterpret_cast<const sockaddr_in *>(&addr)->sin_port));
    return buf;
  }

  logger->error("addr to string failed: {}", strerror(errno));
  return "";
}

int ParseAddr(const char *ipv4, uint16_t host_port, sockaddr_storage &addr) {
  if (inet_pton(AF_INET, ipv4,
                &reinterpret_cast<sockaddr_in *>(&addr)->sin_addr) != 1) {
    logger->error("parse {} failed", ipv4);
    return -1;
  }

  reinterpret_cast<sockaddr_in *>(&addr)->sin_port = htons(host_port);
  reinterpret_cast<sockaddr_in *>(&addr)->sin_family = AF_INET;
  return 0;
}

int SendTo(int fd, const void *buf, ssize_t size,
           const sockaddr_storage &peer_addr) {
  ssize_t sent =
      sendto(fd, buf, size, 0, reinterpret_cast<const sockaddr *>(&peer_addr),
             sizeof(peer_addr));
  if (sent != size) {
    logger->error("failed to send: {}, fd: {}", strerror(errno), fd);
    return -1;
  } else {
    logger->trace("UDP sent {} bytes", sent);
    return 0;
  }
}

}  // namespace quic_tunnel
