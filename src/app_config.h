#ifndef QUIC_TUNNEL_APP_CONFIG_H_
#define QUIC_TUNNEL_APP_CONFIG_H_

#include <arpa/inet.h>

#include <string>

#include "non_copyable.h"

namespace quic_tunnel {

struct AppConfig : NonCopyable {
  bool is_server;
  std::string protocol;
  sockaddr_storage bind_addr;
  sockaddr_storage peer_addr;

  uint32_t tcp_read_watermark;

  bool quic_debug_logging;
  uint32_t idle_timeout;
  uint32_t initial_max_stream_data_bidi_local;
  uint32_t initial_max_stream_data_bidi_remote;
  uint32_t initial_max_streams_bidi;
  uint32_t initial_max_data;
  uint32_t max_payload_size;
  std::string cert_path;
  std::string key_path;

  std::string log_file;
  std::string log_level;
  std::string flush_level;
  std::string log_pattern;
  uint32_t max_log_size;
  uint32_t max_logs;

  [[nodiscard]] static int Load(const std::string& path);

  static const AppConfig& GetInstance() { return GetInstance0(); }

 private:
  static AppConfig& GetInstance0();
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_APP_CONFIG_H_
