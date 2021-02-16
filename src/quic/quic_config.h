#ifndef QUIC_TUNNEL_QUIC_QUIC_CONFIG_H_
#define QUIC_TUNNEL_QUIC_QUIC_CONFIG_H_

#include <quiche.h>

#include "non_copyable.h"
#include "util.h"

namespace quic_tunnel {

struct AppConfig;
class QuicConfig {
 public:
  explicit QuicConfig(const AppConfig& cfg);

  [[nodiscard]] auto max_payload_size() const noexcept {
    return max_payload_size_;
  }

  [[nodiscard]] quiche_config* GetConfig() const noexcept {
    return quiche_config_.get();
  }

 private:
  uint32_t max_payload_size_;
  UniquePtr<quiche_config, quiche_config_free> quiche_config_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_QUIC_CONFIG_H_
