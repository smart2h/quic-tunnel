#include "app_config.h"

#include <fstream>
#include <toml.hpp>

#include "log.h"
#include "util.h"

namespace {

bool ResolvePath(const std::string &current_path, std::string &path) {
  if (path.empty()) {
    return false;
  }

  if (path.front() == '/') {
    return true;
  }

  auto pos = current_path.rfind('/');
  if (pos == std::string::npos) {
    return true;
  }

  path = current_path.substr(0, pos) + "/" + path;
  return true;
}

}  // namespace

namespace quic_tunnel {

int AppConfig::Load(const std::string &path) {
  try {
    auto table = toml::parse(path);
    auto &cfg = GetInstance0();

    const auto &app = toml::find(table, "app");
    cfg.is_server = toml::find<bool>(app, "server_mode");
    cfg.protocol = toml::find_or<std::string>(app, "protocol", "http");
    std::string_view ip = toml::find<std::string>(app, "bind_ip");
    auto port = toml::find<uint16_t>(app, "bind_port");
    if (ip.empty() || port == 0 ||
        ParseAddr(ip.data(), port, cfg.bind_addr) != 0) {
      logger->error("invalid bind_ip:bind_port {}:{}", ip, port);
      return -1;
    }

    ip = toml::find<std::string>(app, "peer_ip");
    port = toml::find<uint16_t>(app, "peer_port");
    if (ip.empty() || port == 0 ||
        ParseAddr(ip.data(), port, cfg.peer_addr) != 0) {
      logger->error("invalid peer_ip:peer_port {}:{}", ip, port);
      return -1;
    }

    const auto &admin = toml::find(table, "admin");
    cfg.admin_bind_ip =
        toml::find_or<std::string>(admin, "bind_ip", "127.0.0.1");
    cfg.admin_bind_port = toml::find<uint16_t>(admin, "bind_port");

    cfg.tcp_read_watermark = 1024 * 1024;
    if (table.contains("tcp")) {
      const auto &tcp = table["tcp"];
      cfg.tcp_read_watermark =
          toml::find_or<uint32_t>(tcp, "read_watermark", 1024 * 1024);
    }

    const auto &quic = toml::find(table, "quic");
    cfg.quic_debug_logging =
        toml::find_or<bool>(quic, "enable_debug_logging", false);
    cfg.idle_timeout = toml::find<uint32_t>(quic, "idle_timeout") * 1000;
    cfg.initial_max_stream_data_bidi_local = toml::find_or<uint32_t>(
        quic, "initial_max_stream_data_bidi_local", 1024 * 1024);
    cfg.initial_max_stream_data_bidi_remote = toml::find_or<uint32_t>(
        quic, "initial_max_stream_data_bidi_remote", 1024 * 1024);
    cfg.initial_max_streams_bidi =
        toml::find_or<uint32_t>(quic, "initial_max_streams_bidi", 128);
    cfg.initial_max_data =
        toml::find_or<uint32_t>(quic, "initial_max_data", 10 * 1024 * 1024);
    cfg.max_payload_size =
        toml::find_or<uint32_t>(quic, "max_payload_size", 1350);
    if (cfg.max_payload_size < 1200 ||
        cfg.max_payload_size > sizeof(quic_buffer)) {
      logger->error("invalid max_payload_size: {}", cfg.max_payload_size);
      return -1;
    }

    if (cfg.is_server) {
      cfg.cert_path = toml::find<std::string>(quic, "cert_chain_path");
      cfg.key_path = toml::find<std::string>(quic, "private_key_path");
      if (!ResolvePath(path, cfg.cert_path) ||
          !ResolvePath(path, cfg.key_path)) {
        logger->error("invalid cert_chain_path or private_key_path");
        return -1;
      }
    } else {
      cfg.initial_max_streams_bidi = 0;
    }

    const auto &log = toml::find(table, "log");
    cfg.log_file = toml::find<std::string>(log, "file");
    if (!ResolvePath(path, cfg.log_file)) {
      logger->error("invalid log file");
      return -1;
    }

    cfg.log_level = toml::find_or<std::string>(log, "level", "info");
    cfg.flush_level = toml::find_or<std::string>(log, "flush_level", "warn");
    cfg.log_pattern = toml::find_or<std::string>(log, "pattern", "");
    cfg.max_log_size =
        toml::find_or<uint32_t>(log, "max_size", 20) * 1024 * 1024;
    cfg.max_logs = toml::find_or<uint32_t>(log, "max_files", 5);
  } catch (const std::exception &ex) {
    logger->error("failed to parse {}, {}", path, ex.what());
    return -1;
  }
  return 0;
}

AppConfig &AppConfig::GetInstance0() {
  static AppConfig cfg;
  return cfg;
}

}  // namespace quic_tunnel
