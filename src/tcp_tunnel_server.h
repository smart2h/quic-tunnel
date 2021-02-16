#ifndef QUIC_TUNNEL_TCP_TUNNEL_SERVER_H_
#define QUIC_TUNNEL_TCP_TUNNEL_SERVER_H_

#include "event/event_base.h"
#include "quic/connection_callbacks_factory.h"
#include "quic/quic_config.h"
#include "quic/quic_server.h"

namespace quic_tunnel {

class TcpTunnelServer : NonCopyable, ConnectionCallbacksFactory {
 public:
  TcpTunnelServer(const QuicConfig &quic_config, EventBase &base)
      : base_(base), quic_server_(quic_config, base, *this) {}

  int Bind() { return quic_server_.Bind(); }

  std::unique_ptr<ConnectionCallbacks> Create() override;

 private:
  EventBase &base_;
  QuicServer quic_server_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_SERVER_H_
