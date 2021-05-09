#include "tcp_tunnel_server.h"

#include <event2/bufferevent.h>

#include "tcp_tunnel_callbacks.h"
#include "util.h"

namespace quic_tunnel {

namespace {

class ServerConnectionCallbacks : public TcpTunnelCallbacks {
 public:
  ServerConnectionCallbacks(EventBase &base, Admin &admin)
      : TcpTunnelCallbacks(admin), base_(base) {}

 private:
  bufferevent *OnNewStream() override {
    auto *bev = bufferevent_socket_new(
        base_.base(), -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    assert(bev);
    const auto &cfg = AppConfig::GetInstance();
    if (bufferevent_socket_connect(
            bev, reinterpret_cast<const sockaddr *>(&cfg.peer_addr),
            sizeof(cfg.peer_addr)) != 0) {
      logger->error("failed to connect to {}, {}", ToString(cfg.peer_addr),
                    strerror(errno));
      bufferevent_free(bev);
      return nullptr;
    }

    bufferevent_setcb(bev, ReadCallback, nullptr, EventCallback, this);
    bufferevent_setwatermark(bev, EV_READ, 0, cfg.tcp_read_watermark);
    if (bufferevent_enable(bev, EV_READ | EV_WRITE) != 0) {
      logger->error("failed to enable buffer event");
      bufferevent_free(bev);
    }

    return bev;
  }

  EventBase &base_;
};

}  // namespace

std::unique_ptr<ConnectionCallbacks> TcpTunnelServer::Create() {
  return std::make_unique<ServerConnectionCallbacks>(base_, admin_);
}

}  // namespace quic_tunnel
