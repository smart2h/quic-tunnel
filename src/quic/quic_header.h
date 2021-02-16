#ifndef QUIC_TUNNEL_QUIC_QUIC_HEADER_H_
#define QUIC_TUNNEL_QUIC_QUIC_HEADER_H_

#include <quiche.h>
#include <sys/socket.h>

#include <array>

namespace quic_tunnel {

inline constexpr int kConnectionIdBytes = 16;

inline constexpr int kIvBytes = 12;
inline constexpr int kMacTagBytes = 16;
inline constexpr int kTokenBytes =
    4 + 2 + kConnectionIdBytes * 2 + 8 + kIvBytes +
    kMacTagBytes;  // ip + port + scid + dcid + timestamp

using ConnectionId = std::array<uint8_t, kConnectionIdBytes>;

struct QuicHeader {
  uint8_t type;
  uint32_t version;
  size_t token_len;
  ConnectionId scid;
  ConnectionId dcid;
  uint8_t token[kTokenBytes];

  [[nodiscard]] static int Parse(const uint8_t *buf, size_t buf_len,
                                 QuicHeader &header);
  int MintToken(const sockaddr_storage &addr);
  bool ValidateToken(const sockaddr_storage &addr, ConnectionId &odcid);
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_QUIC_HEADER_H_
