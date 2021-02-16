#ifndef QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
#define QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_

#include <event2/listener.h>

#include "app_config.h"
#include "quic/quic_client.h"
#include "stream_id_generator.h"
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

  bool IsEstablished() override {
    return quic_client_.connection().IsEstablished();
  }

  Connection &connection() override { return quic_client_.connection(); }

  void OnQuicConnectionClosed() override { stream_id_generator_.Reset(); }

  bufferevent *OnNewStream(StreamId stream_id) override;
  void OnConnected(Connection &) override;
  void NewStream(bufferevent *bev);
  [[nodiscard]] auto HexId();

  UniquePtr<evconnlistener, evconnlistener_free> listener_;
  QuicClient quic_client_;
  StreamIdGenerator stream_id_generator_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
