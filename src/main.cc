#include <csignal>
#include <iostream>

#include "admin.h"
#include "tcp_tunnel_client.h"
#include "tcp_tunnel_server.h"
using namespace quic_tunnel;

namespace {

int IgnoreSigpipe() {
  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  if (sigemptyset(&action.sa_mask) != 0) {
    return -1;
  }

  if (sigaction(SIGPIPE, &action, nullptr) != 0) {
    return -1;
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 3 || argv[1] != std::string_view("-c")) {
    std::cerr << "Unknown options" << std::endl;
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  " << argv[0] << " -c path/to/config" << std::endl;
    return -1;
  }

  if (AppConfig::Load(argv[2]) != 0) {
    return -1;
  }

  const auto &cfg = AppConfig::GetInstance();
  if (InitLogger(cfg) != 0) {
    return -1;
  }

  if (cfg.quic_debug_logging) {
    quiche_enable_debug_logging([](const char *p, void *) { logger->trace(p); },
                                nullptr);
  }

  QuicConfig quic_config(cfg);
  if (!quic_config.GetConfig()) {
    return -1;
  }

  if (IgnoreSigpipe() != 0) {
    logger->error("failed to ignore SIGPIPE: {}", strerror(errno));
    return -1;
  }

  EventBase base;
  Admin admin(base);
  if (admin.Bind() != 0) {
    return -1;
  }

  if (cfg.is_server) {
    TcpTunnelServer server(quic_config, base, admin);
    if (server.Bind() != 0) {
      return -1;
    }
    return base.Dispatch();
  } else {
    TcpTunnelClient client(quic_config, base, admin);
    if (client.Bind(cfg, base)) {
      return -1;
    }
    return base.Dispatch();
  }
}
