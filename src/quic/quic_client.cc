#include "quic/quic_client.h"

#include <spdlog/fmt/bin_to_hex.h>

#include <memory>

#include "app_config.h"
#include "util.h"

namespace quic_tunnel {

QuicClient::QuicClient(const QuicConfig &quic_config, EventBase &base,
                       ConnectionCallbacks &connection_callbacks)
    : quic_config_(quic_config),
      base_(base),
      connection_callbacks_(connection_callbacks),
      fd_(0) {}

int QuicClient::Connect() {
  if (UdpConnect() != 0) {
    return -1;
  }

  const auto &cfg = AppConfig::GetInstance();
  connection_ = std::make_unique<Connection>(
      quic_config_, base_, fd_, connection_callbacks_, cfg.peer_addr);
  return connection_->Connect();
}

int QuicClient::UdpConnect() {
  if (fd_ > 0) {
    return 0;
  }

  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ == -1) {
    logger->error("failed to create socket: {}", strerror(errno));
    return -1;
  }

  const auto &cfg = AppConfig::GetInstance();
  if (connect(fd_, reinterpret_cast<const sockaddr *>(&cfg.peer_addr),
              sizeof(cfg.peer_addr)) != 0) {
    logger->error("failed to connect: {}", strerror(errno));
    Close();
    return -1;
  }

  if (evutil_make_socket_nonblocking(fd_) != 0) {
    logger->error("failed to make socket non-blocking: {}", strerror(errno));
    Close();
    return -1;
  }

  event_ = base_.NewEvent(fd_, EV_READ | EV_PERSIST, ReadCallback, this);
  if (event_->Enable() != 0) {
    Close();
    return -1;
  }

  logger->info("UDP connected to {}, fd: {}", ToString(cfg.peer_addr), fd_);
  return 0;
}

void QuicClient::Close() {
  if (fd_ > 0) {
    connection_->Close();
    if (close(fd_) != 0) {
      logger->error("close fd {} failed: {}", fd_, strerror(errno));
    }
    fd_ = 0;
  }
}

void QuicClient::ReadCallback(int fd, short, void *arg) {
  auto *client = static_cast<QuicClient *>(arg);
  while (true) {
    ssize_t count = recv(fd, udp_buffer, sizeof(udp_buffer), 0);
    if (count < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        break;
      } else {
        logger->error("recv error: {}, fd: {}", strerror(errno), fd);
        return;
      }
    }

    logger->trace("UDP recv {} bytes", count);

    QuicHeader header;
    if (auto r = QuicHeader::Parse(udp_buffer, count, header); r < 0) {
      logger->warn("failed to parse header: {}", r);
      continue;
    }

    if (header.dcid != client->connection_->id()) {
      logger->warn("invalid cid {:spn}", spdlog::to_hex(header.dcid));
      continue;
    }

    client->connection_->OnRead(udp_buffer, count, sizeof(udp_buffer));
  }
}

}  // namespace quic_tunnel
