#include "quic/quic_server.h"

#include <spdlog/fmt/bin_to_hex.h>

#include "quic/quic_header.h"
#include "util.h"

namespace quic_tunnel {

namespace {

int NegotiateVersion(const QuicHeader &header, int fd,
                     const sockaddr_storage &peer_addr,
                     uint32_t max_payload_size) {
  ssize_t written = quiche_negotiate_version(
      header.scid.data(), header.scid.size(), header.dcid.data(),
      header.dcid.size(), quic_buffer, max_payload_size);
  if (written <= 0) {
    logger->error("failed to create version negotiate packet: {}, fd: {}",
                  written, fd);
    return -1;
  }
  return SendTo(fd, quic_buffer, written, peer_addr);
}

int StatelessRetry(QuicHeader &header, int fd,
                   const sockaddr_storage &peer_addr,
                   uint32_t max_payload_size) {
  if (header.MintToken(peer_addr) != 0) {
    return -1;
  }

  ConnectionId new_cid;
  evutil_secure_rng_get_bytes(new_cid.data(), new_cid.size());
  logger->debug("new cid {:spn}", spdlog::to_hex(new_cid));

  ssize_t written = quiche_retry(
      header.scid.data(), header.scid.size(), header.dcid.data(),
      header.dcid.size(), new_cid.data(), new_cid.size(), header.token,
      header.token_len, header.version, quic_buffer, max_payload_size);
  if (written < 0) {
    logger->error("failed to create retry packet: {}, fd: {}", written, fd);
    return -1;
  }
  return SendTo(fd, quic_buffer, written, peer_addr);
}

}  // namespace

QuicServer::QuicServer(const QuicConfig &quic_config, EventBase &base,
                       ConnectionCallbacksFactory &connection_callbacks_factory)
    : quic_config_(quic_config),
      base_(base),
      connection_callbacks_factory_(connection_callbacks_factory),
      fd_(0) {}

int QuicServer::Bind() {
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ == -1) {
    logger->error("failed to create socket: {}", strerror(errno));
    return -1;
  }

  if (evutil_make_socket_nonblocking(fd_) != 0) {
    logger->error("failed to make socket non-blocking: {}", strerror(errno));
    Close();
    return -1;
  }

  const auto &cfg = AppConfig::GetInstance();
  if (bind(fd_, reinterpret_cast<const sockaddr *>(&cfg.bind_addr),
           sizeof(cfg.bind_addr)) != 0) {
    logger->error("failed to bind to {}, {}", ToString(cfg.bind_addr),
                  strerror(errno));
    Close();
    return -1;
  }

  event_ = base_.NewEvent(fd_, EV_READ | EV_PERSIST, ReadCallback, this);
  if (event_->Enable() != 0) {
    Close();
    return -1;
  }

  logger->info("listening on {}, fd: {}", ToString(cfg.bind_addr), fd_);
  return 0;
}

void QuicServer::Close() {
  if (fd_ > 0) {
    logger->info("closing {} connections", connections_.size());
    for (const auto &pair : connections_) {
      pair.second.first->Close();
    }
    connections_.clear();

    if (close(fd_) != 0) {
      logger->error("close fd {} failed: {}", fd_, strerror(errno));
    }
    fd_ = 0;
  }
}

auto QuicServer::Handshake(QuicHeader &header,
                           const sockaddr_storage &peer_addr, int fd) {
  if (!quiche_version_is_supported(header.version)) {
    NegotiateVersion(header, fd, peer_addr, quic_config_.max_payload_size());
    return connections_.end();
  }

  if (header.token_len == 0) {
    StatelessRetry(header, fd, peer_addr, quic_config_.max_payload_size());
    return connections_.end();
  }

  ConnectionId odcid;
  if (!header.ValidateToken(peer_addr, odcid)) {
    logger->warn("invalid address validation token, client addr {}",
                 ToString(peer_addr));
    return connections_.end();
  }

  auto connection_callbacks = connection_callbacks_factory_.Create();
  auto connection = std::make_unique<Connection>(
      quic_config_, base_, fd, *connection_callbacks, peer_addr);
  if (connection->Accept(header.dcid, odcid, header.scid) != 0) {
    return connections_.end();
  }

  auto conn_id = connection->id();
  auto pair = connections_.emplace(
      conn_id,
      std::make_pair(std::move(connection), std::move(connection_callbacks)));
  return pair.first;
}

void QuicServer::ReadCallback(int fd, short, void *arg) {
  auto *server = static_cast<QuicServer *>(arg);
  sockaddr_storage peer_addr{};
  socklen_t peer_addr_len = sizeof(peer_addr);
  while (true) {
    auto count =
        recvfrom(fd, udp_buffer, sizeof(udp_buffer), 0,
                 reinterpret_cast<sockaddr *>(&peer_addr), &peer_addr_len);
    if (count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else {
        logger->error("recvfrom error: {}, fd: {}", strerror(errno), fd);
        return;
      }
    }
    logger->trace("UDP recv {} bytes", count);

    QuicHeader header;
    if (auto r = QuicHeader::Parse(udp_buffer, count, header); r < 0) {
      logger->warn("failed to parse header: {}, client addr {}", r,
                   ToString(peer_addr));
      continue;
    }

    logger->trace("QUIC header: type={:d} version={} scid={:spn} dcid={:spn}",
                  header.type, header.version, spdlog::to_hex(header.scid),
                  spdlog::to_hex(header.dcid));

    auto iter = server->connections_.find(header.dcid);
    if (iter == server->connections_.end()) {
      iter = server->Handshake(header, peer_addr, fd);
      if (iter == server->connections_.end()) {
        continue;
      }
    }
    iter->second.first->OnRead(udp_buffer, count, sizeof(udp_buffer));
  }
}

}  // namespace quic_tunnel
