#ifndef QUIC_TUNNEL_LOG_H_
#define QUIC_TUNNEL_LOG_H_

#include <spdlog/spdlog.h>

#include "app_config.h"

namespace quic_tunnel {

extern std::shared_ptr<spdlog::logger> logger;

int InitLogger(const AppConfig &cfg);

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_LOG_H_
