#include "tcp_tunnel_client.h"

#include <event2/bufferevent.h>

namespace quic_tunnel {

int TcpTunnelClient::Bind(const AppConfig &cfg, EventBase &base) {
  if (quic_client_.Connect() != 0) {
    return -1;
  }

  listener_.reset(evconnlistener_new_bind(
      base.base(), AcceptCallback, this,
      LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 128,
      reinterpret_cast<const sockaddr *>(&cfg.bind_addr),
      sizeof(cfg.bind_addr)));
  if (!listener_) {
    logger->error("failed to bind to {}, {}", ToString(cfg.bind_addr),
                  strerror(errno));
    return -1;
  }
  return 0;
}

TcpTunnelCallbacks::Status TcpTunnelClient::OnTcpRead() {
  if (quic_client_.connection().IsEstablished()) {
    return TcpTunnelCallbacks::Status::kReady;
  }

  if (quic_client_.connection().IsClosed()) {
    quic_client_.Connect();
  }
  return TcpTunnelCallbacks::Status::kUnready;
}

void TcpTunnelClient::AcceptCallback(evconnlistener *listener,
                                     evutil_socket_t fd, sockaddr *, int,
                                     void *ctx) {
  auto client = static_cast<TcpTunnelClient *>(ctx);
  if (client->IsEstablished() &&
      client->quic_client_.connection().PeerStreamsLeft() == 0) {
    logger->warn("no peer streams left");
    evutil_closesocket(fd);
    return;
  }

  auto base = evconnlistener_get_base(listener);
  bufferevent *bev = bufferevent_socket_new(
      base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  if (!bev) {
    logger->error("failed to create socket buffer event");
    evutil_closesocket(fd);
    return;
  }

  bufferevent_setcb(bev, ReadCallback, nullptr, EventCallback, ctx);
  bufferevent_setwatermark(bev, EV_READ, 0,
                           AppConfig::GetInstance().tcp_read_watermark);
  if (bufferevent_enable(bev, EV_READ | EV_WRITE) != 0) {
    logger->error("failed to enable buffer event");
    bufferevent_free(bev);
    evutil_closesocket(fd);
  }
}

}  // namespace quic_tunnel
