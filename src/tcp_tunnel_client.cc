#include "tcp_tunnel_client.h"

#include <event2/bufferevent.h>

namespace quic_tunnel {
namespace {

class ClientConnectionCallbacks : public TcpTunnelCallbacks {
 public:
  explicit ClientConnectionCallbacks(Admin &admin)
      : TcpTunnelCallbacks(admin){};

  void OnNewTcpConnection(bufferevent *bev) {
    bufferevent_setcb(bev, ReadCallback, nullptr, EventCallback, this);
    ReadCallback(bev, this);
  }

 private:
  bufferevent *OnNewStream() override { return nullptr; };
};

}  // namespace

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

void TcpTunnelClient::AcceptCallback(evconnlistener *listener,
                                     evutil_socket_t fd, sockaddr *, int,
                                     void *ctx) {
  auto client = static_cast<TcpTunnelClient *>(ctx);
  if (client->tcp_tunnel_callbacks_ &&
      client->quic_client_.connection()->PeerStreamsLeft() == 0) {
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

void TcpTunnelClient::ReadCallback(bufferevent *bev, void *ctx) {
  auto *client = static_cast<TcpTunnelClient *>(ctx);
  if (client->tcp_tunnel_callbacks_) {
    dynamic_cast<ClientConnectionCallbacks *>(
        client->tcp_tunnel_callbacks_.get())
        ->OnNewTcpConnection(bev);
  } else {
    if (!client->quic_client_.connection() ||
        client->quic_client_.connection()->IsClosed()) {
      if (client->quic_client_.Connect() != 0) {
        bufferevent_free(bev);
        return;
      }
    }

    client->waiting_bevs_.emplace(bev);
    bufferevent_disable(bev, EV_READ);
    logger->info("waiting for connected, waiting queue {}",
                 client->waiting_bevs_.size());
  }
}

void TcpTunnelClient::EventCallback(bufferevent *bev, short what, void *) {
  if (what & BEV_EVENT_ERROR) {
    logger->warn("buffer event socket error: {}", strerror(errno));
  }

  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    bufferevent_free(bev);
  } else {
    logger->warn("invalid events: {}", static_cast<int>(what));
  }
}

void TcpTunnelClient::OnConnected(Connection &connection) {
  auto callbacks = std::make_unique<ClientConnectionCallbacks>(admin_);
  static_cast<ConnectionCallbacks *>(callbacks.get())->OnConnected(connection);
  for (auto iter = waiting_bevs_.cbegin(); iter != waiting_bevs_.cend();) {
    bufferevent_enable(*iter, EV_READ);
    callbacks->OnNewTcpConnection(*iter);
    iter = waiting_bevs_.erase(iter);
  }
  tcp_tunnel_callbacks_ = std::move(callbacks);
  connection.AddConnectionCallbacks(*tcp_tunnel_callbacks_);
}

void TcpTunnelClient::OnClosed() {
  tcp_tunnel_callbacks_.reset();
  for (auto iter = waiting_bevs_.cbegin(); iter != waiting_bevs_.cend();) {
    bufferevent_free(*iter);
    iter = waiting_bevs_.erase(iter);
  }
}

}  // namespace quic_tunnel
