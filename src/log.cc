#include "log.h"

#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace {

std::optional<spdlog::level::level_enum> ToLevel(const std::string &s) {
  if (s == "trace") {
    return spdlog::level::trace;
  } else if (s == "debug") {
    return spdlog::level::debug;
  } else if (s == "info") {
    return spdlog::level::info;
  } else if (s == "warn") {
    return spdlog::level::warn;
  } else if (s == "error") {
    return spdlog::level::err;
  } else if (s == "critical") {
    return spdlog::level::critical;
  } else {
    return {};
  }
}

}  // namespace

namespace quic_tunnel {

std::shared_ptr<spdlog::logger> logger = spdlog::stderr_color_st("quic-tunnel");

int InitLogger(const AppConfig &cfg) {
  spdlog::sink_ptr sink;
  if (cfg.log_file == "/dev/stdout") {
    sink = std::make_shared<spdlog::sinks::stdout_color_sink_st>();
  } else if (cfg.log_file == "/dev/stderr") {
    sink = std::make_shared<spdlog::sinks::stderr_color_sink_st>();
  } else if (cfg.log_file == "/dev/null") {
    sink = std::make_shared<spdlog::sinks::null_sink_st>();
  } else {
    try {
      sink = std::make_shared<spdlog::sinks::rotating_file_sink_st>(
          cfg.log_file, cfg.max_log_size, cfg.max_logs);
    } catch (const spdlog::spdlog_ex &ex) {
      logger->error(ex.what());
      return -1;
    }
  }

  logger = std::make_shared<spdlog::logger>("quic-tunnel", sink);
  logger->set_level(ToLevel(cfg.log_level).value_or(spdlog::level::info));
  logger->flush_on(ToLevel(cfg.flush_level).value_or(spdlog::level::warn));
  if (!cfg.log_pattern.empty()) {
    logger->set_pattern(cfg.log_pattern);
  }
  return 0;
}

}  // namespace quic_tunnel
