#ifndef QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
#define QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_

#include <event2/listener.h>

#include "app_config.h"
#include "quic/quic_client.h"
#include "tcp_tunnel_callbacks.h"

namespace quic_tunnel {

class TcpTunnelClient : TcpTunnelCallbacks {
 public:
  TcpTunnelClient(const QuicConfig &quic_config, EventBase &base)
      : quic_client_(quic_config, base, *this) {}

  int Bind(const AppConfig &, EventBase &);

 private:
  static void AcceptCallback(evconnlistener *listener, evutil_socket_t fd,
                             sockaddr *, int, void *);
  Status OnTcpRead() override;

  bufferevent *OnNewStream() override { return nullptr; };

  UniquePtr<evconnlistener, evconnlistener_free> listener_;
  QuicClient quic_client_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
