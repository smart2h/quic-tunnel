#ifndef QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
#define QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_

#include <event2/listener.h>

#include "app_config.h"
#include "quic/quic_client.h"
#include "tcp_tunnel_callbacks.h"

namespace quic_tunnel {

class Admin;
class TcpTunnelClient : NonCopyable, ConnectionCallbacks {
 public:
  TcpTunnelClient(const QuicConfig &quic_config, EventBase &base, Admin &admin)
      : admin_(admin), quic_client_(quic_config, base, *this) {}
  ~TcpTunnelClient() override { OnClosed(); }

  int Bind(const AppConfig &, EventBase &);

 private:
  static void AcceptCallback(evconnlistener *listener, evutil_socket_t fd,
                             sockaddr *, int, void *);
  static void ReadCallback(bufferevent *bev, void *ctx);
  static void EventCallback(bufferevent *bev, short what, void *);
  void OnClosed();

  void OnConnected(Connection &) override;
  void OnClosed(Connection &) override { OnClosed(); }
  void OnStreamRead(StreamId, const uint8_t *, size_t, bool) override{};
  void OnStreamWrite(StreamId) override {}
  [[nodiscard]] bool ReportWritableStreams() const override { return false; }

  Admin &admin_;
  UniquePtr<evconnlistener, evconnlistener_free> listener_;
  QuicClient quic_client_;
  std::set<bufferevent *> waiting_bevs_;
  std::unique_ptr<TcpTunnelCallbacks> tcp_tunnel_callbacks_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CLIENT_H_
