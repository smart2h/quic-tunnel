#ifndef QUIC_TUNNEL_QUIC_QUIC_CLIENT_H_
#define QUIC_TUNNEL_QUIC_QUIC_CLIENT_H_

#include "quic/connection.h"

namespace quic_tunnel {

class QuicClient : NonCopyable {
 public:
  QuicClient(const QuicConfig &quic_config, EventBase &base,
             ConnectionCallbacks &connection_callbacks);
  ~QuicClient() { Close(); }

  int Connect();

  Connection *connection() noexcept { return connection_.get(); }

 private:
  static void ReadCallback(int, short, void *);
  int UdpConnect();
  void Close();

  const QuicConfig &quic_config_;
  EventBase &base_;
  ConnectionCallbacks &connection_callbacks_;
  int fd_;
  std::unique_ptr<Event> event_;
  std::unique_ptr<Connection> connection_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_QUIC_CLIENT_H_
