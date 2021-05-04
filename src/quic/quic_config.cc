#include "quic/quic_config.h"

#include "log.h"

namespace quic_tunnel {

QuicConfig::QuicConfig(const AppConfig &cfg)
    : max_payload_size_(cfg.max_payload_size) {
  decltype(quiche_config_) quiche_config(
      quiche_config_new(QUICHE_PROTOCOL_VERSION));
  if (!quiche_config) {
    logger->error("failed to create quiche config");
    return;
  }

  if (cfg.is_server) {
    if (quiche_config_load_cert_chain_from_pem_file(
            quiche_config.get(), cfg.cert_path.c_str()) != 0) {
      logger->error("failed to load cert chain from {}", cfg.cert_path);
      return;
    }

    if (quiche_config_load_priv_key_from_pem_file(quiche_config.get(),
                                                  cfg.key_path.c_str()) != 0) {
      logger->error("failed to load private key from {}", cfg.key_path);
      return;
    }
  }

  uint8_t protos[32];
  if (cfg.protocol.length() >= sizeof(protos)) {
    logger->error("length of application protocol is too long");
    return;
  }

  protos[0] = cfg.protocol.length();
  memcpy(protos + 1, cfg.protocol.data(), cfg.protocol.length());
  if (quiche_config_set_application_protos(quiche_config.get(), protos,
                                           cfg.protocol.length() + 1)) {
    logger->error("failed to set application protocols");
    return;
  }

  quiche_config_ = std::move(quiche_config);
  quiche_config_set_disable_active_migration(quiche_config_.get(), true);
  quiche_config_set_max_idle_timeout(quiche_config_.get(), cfg.idle_timeout);
  quiche_config_set_max_recv_udp_payload_size(quiche_config_.get(),
                                              max_payload_size_);
  quiche_config_set_max_send_udp_payload_size(quiche_config_.get(),
                                              max_payload_size_);
  quiche_config_set_initial_max_data(quiche_config_.get(),
                                     cfg.initial_max_data);
  quiche_config_set_initial_max_stream_data_bidi_local(
      quiche_config_.get(), cfg.initial_max_stream_data_bidi_local);
  quiche_config_set_initial_max_stream_data_bidi_remote(
      quiche_config_.get(), cfg.initial_max_stream_data_bidi_remote);
  quiche_config_set_initial_max_streams_bidi(quiche_config_.get(),
                                             cfg.initial_max_streams_bidi);
  quiche_config_set_cc_algorithm(quiche_config_.get(), QUICHE_CC_CUBIC);
}

}  // namespace quic_tunnel
