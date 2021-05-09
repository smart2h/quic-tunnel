#include "admin.h"

#include <event2/buffer.h>

#include "app_config.h"

namespace quic_tunnel {

Admin::Admin(EventBase &base)
    : base_(base),
      http_(evhttp_new(base_.base())),
      timer_(base_.NewTimer(
          [](int, short, void *arg) {
            static_cast<Admin *>(arg)->base_.Exit();
          },
          this)) {
  if (!http_) {
    logger->error("failed to create evhttp");
    throw std::runtime_error("failed to create evhttp");
  }

  if (evhttp_set_cb(http_.get(), "/stats", StatsCallback, this) != 0) {
    logger->error("failed to register callback for /stats");
    throw std::runtime_error("failed to register callback for /stats");
  }

  if (evhttp_set_cb(http_.get(), "/quit", QuitCallback, this) != 0) {
    logger->error("failed to register callback for /quit");
    throw std::runtime_error("failed to register callback for /quit");
  }
}

int Admin::Bind() {
  const auto &cfg = AppConfig::GetInstance();
  if (evhttp_bind_socket(http_.get(), cfg.admin_bind_ip.c_str(),
                         cfg.admin_bind_port) != 0) {
    logger->error("failed to bind to {}:{}", cfg.admin_bind_ip,
                  cfg.admin_bind_port);
    return -1;
  }

  logger->info("admin listening on {}:{}", cfg.admin_bind_ip,
               cfg.admin_bind_port);
  return 0;
}

void Admin::Register(TcpTunnelCallbacks &callbacks) {
  tcp_tunnel_callbacks_set_.emplace(&callbacks);
}

void Admin::Unregister(TcpTunnelCallbacks &callbacks) {
  tcp_tunnel_callbacks_set_.erase(&callbacks);
  if (closing_ && tcp_tunnel_callbacks_set_.empty()) {
    base_.Exit();
  }
}

void Admin::StatsCallback(evhttp_request *req, void *arg) {
  auto *headers = evhttp_request_get_output_headers(req);
  evhttp_add_header(headers, "content-type", "text/plain");

  const auto *admin = static_cast<Admin *>(arg);
  auto *evb = evhttp_request_get_output_buffer(req);
  for (const auto *callbacks : admin->tcp_tunnel_callbacks_set_) {
    callbacks->Stats(evb);
    evbuffer_add(evb, "\n", 1);
  }
  evhttp_send_reply(req, 200, "OK", nullptr);
}

void Admin::QuitCallback(evhttp_request *req, void *arg) {
  auto cmd = evhttp_request_get_command(req);
  if (cmd != EVHTTP_REQ_POST) {
    auto *evb = evhttp_request_get_output_buffer(req);
    static constexpr std::string_view body = "POST required";
    evbuffer_add(evb, body.data(), body.length());
    evhttp_send_reply(req, 405, "Method Not Allowed", nullptr);
    return;
  }

  auto *admin = static_cast<Admin *>(arg);
  for (auto *callbacks : admin->tcp_tunnel_callbacks_set_) {
    callbacks->Close();
  }
  evhttp_send_reply(req, 200, "OK", nullptr);

  admin->closing_ = true;
  if (admin->tcp_tunnel_callbacks_set_.empty()) {
    admin->timer_.Enable(0);
  }
}

}  // namespace quic_tunnel
