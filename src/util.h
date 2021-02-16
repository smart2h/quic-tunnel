#ifndef QUIC_TUNNEL_UTIL_H_
#define QUIC_TUNNEL_UTIL_H_

#include <arpa/inet.h>

#include <memory>

namespace quic_tunnel {

extern uint8_t udp_buffer[65535];
extern uint8_t quic_buffer[65500];

template <auto T>
using ConstantType = std::integral_constant<std::decay_t<decltype(T)>, T>;
template <class T, auto dtor>
using UniquePtr = std::unique_ptr<T, ConstantType<dtor>>;

const char *ToString(const sockaddr_storage &addr);
int ParseAddr(const char *ipv4, uint16_t host_port, sockaddr_storage &addr);
int SendTo(int fd, const void *buf, ssize_t size,
           const sockaddr_storage &peer_addr);

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_UTIL_H_
