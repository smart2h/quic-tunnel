#include "quic/connection.h"

#include <spdlog/fmt/bin_to_hex.h>

#include <algorithm>

#include "log.h"
#include "quic/quic_header.h"
#include "util.h"

namespace quic_tunnel {

Connection::Connection(const QuicConfig &quic_config, EventBase &base, int fd,
                       ConnectionCallbacks &connection_callbacks,
                       const sockaddr_storage &peer_addr)
    : quic_config_(quic_config),
      fd_(fd),
      timer_(base.NewTimer(
          [](int, short, void *arg) {
            static_cast<Connection *>(arg)->OnTimeout();
          },
          this)),
      conn_(nullptr),
      id_(),
      peer_addr_(peer_addr) {
  callbacks_.emplace_back(&connection_callbacks);
}

Connection::~Connection() {
  if (conn_) {
    Close();
    OnClosed();
  }
}

auto Connection::HexId() const { return spdlog::to_hex(id_); }

void Connection::Close() {
  if (conn_) {
    if (!IsClosed()) {
      logger->info("closing QUIC connection {:spn}", HexId());
      if (auto r = quiche_conn_close(conn_, true, 0, nullptr, 0); r != 0) {
        logger->error("failed to close QUIC connection {:spn}, error {}",
                      HexId(), r);
      } else {
        FlushEgress();
      }
    }
  }
}

void Connection::Close(StreamId stream_id) {
  ShutdownRead(stream_id);
  Send(stream_id, nullptr, 0, true);
}

void Connection::ShutdownRead(StreamId stream_id) {
  quiche_conn_stream_shutdown(conn_, stream_id, QUICHE_SHUTDOWN_READ, 0);
}

void Connection::AddConnectionCallbacks(ConnectionCallbacks &callbacks) {
  callbacks_.emplace_back(&callbacks);
}

int Connection::Accept(const ConnectionId &dcid, const ConnectionId &odcid,
                       const ConnectionId &scid) {
  assert(!conn_);
  conn_ = quiche_accept(dcid.data(), dcid.size(), odcid.data(), odcid.size(),
                        quic_config_.GetConfig());
  id_ = dcid;
  if (!conn_) {
    logger->error(
        "failed to create server QUIC connection {:spn}, scid {:spn}, client "
        "addr {}",
        HexId(), spdlog::to_hex(scid), ToString(peer_addr_));
    return -1;
  } else {
    logger->info(
        "new server QUIC connection {:spn}, scid {:spn}, client addr {}",
        HexId(), spdlog::to_hex(scid), ToString(peer_addr_));
    return 0;
  }
}

int Connection::Connect() {
  assert(!conn_);
  evutil_secure_rng_get_bytes(id_.data(), id_.size());
  conn_ = quiche_connect("name", id_.data(), id_.size(),
                         quic_config_.GetConfig());  // TODO server name
  if (!conn_) {
    logger->error("failed to create client QUIC connection");
    return -1;
  } else {
    logger->info("new client QUIC connection {:spn}", HexId());
    return FlushEgress();
  }
}

int Connection::FlushEgress() {
  while (true) {
    ssize_t written =
        quiche_conn_send(conn_, quic_buffer, quic_config_.max_payload_size());
    if (written == QUICHE_ERR_DONE) {
      break;
    }

    if (written < 0) {
      logger->error("failed to create packet: {}, cid {:spn}", written,
                    HexId());
      return -1;
    }

    if (SendTo(fd_, quic_buffer, written, peer_addr_) != 0) {
      return -1;  // TODO close connection
    }
  }

  auto nanoseconds = quiche_conn_timeout_as_nanos(conn_);
  return timer_.Enable(nanoseconds / 1000 + 1);
}

int Connection::OnRead(uint8_t *buf, size_t len, size_t size) {
  if (!conn_) {
    logger->warn("recv data on closed connection {:spn}", HexId());
    return -1;
  }

  auto count = quiche_conn_recv(conn_, buf, len);
  if (count < 0) {
    logger->error("failed to process packet: {}, cid {:spn}", count, HexId());
    return -1;
  }

  if (IsEstablished()) {
    if (!connected_) {
      connected_ = true;
      logger->info("QUIC connected, cid {:spn}", HexId());
      OnConnected();
    }

    auto stream_iter = quiche_conn_readable(conn_);
    for (StreamId stream_id;
         quiche_stream_iter_next(stream_iter, &stream_id);) {
      OnStreamRead(stream_id, buf, size);
    }
    quiche_stream_iter_free(stream_iter);
  }

  auto r = FlushEgress();
  ReportWritableStreams();
  return r;
}

void Connection::OnStreamRead(StreamId stream_id, uint8_t *buf, size_t size) {
  bool finished{};
  ssize_t count;
  do {
    count = quiche_conn_stream_recv(conn_, stream_id, buf, size, &finished);
    if (count == QUICHE_ERR_DONE) {
      break;
    } else if (count < 0) {
      logger->error("stream {} recv error: {}, cid {:spn}", stream_id, count,
                    HexId());
      break;
    } else {
      logger->trace("stream {} recv {} bytes, cid {:spn}", stream_id, count,
                    HexId());
      OnStreamRead(stream_id, buf, count, finished);
    }
  } while (!(static_cast<size_t>(count) < size || finished));
}

void Connection::OnStreamRead(StreamId stream_id, const uint8_t *buf,
                              size_t count, bool finished) {
  for (auto *callbacks : callbacks_) {
    callbacks->OnStreamRead(stream_id, buf, count, finished);
  }
}

void Connection::OnTimeout() {
  quiche_conn_on_timeout(conn_);
  FlushEgress();
  if (IsClosed()) {
    OnClosed();
  }
}

void Connection::OnConnected() {
  for (auto *callbacks : callbacks_) {
    callbacks->OnConnected(*this);
  }
}

void Connection::OnClosed() {
  std::for_each(callbacks_.crbegin(), callbacks_.crend(),
                [this](auto *callbacks) { callbacks->OnClosed(*this); });
  Stats();
  quiche_conn_free(conn_);
  conn_ = nullptr;
  timer_.Disable();
}

void Connection::Stats() const {
  quiche_stats stats;
  quiche_conn_stats(conn_, &stats);
  logger->info(
      "QUIC connection {:spn} closed, recv={} sent={} lost={} rtt={}ns cwnd={} "
      "delivery_rate={}bytes/s",
      HexId(), stats.recv, stats.sent, stats.lost, stats.rtt, stats.cwnd,
      stats.delivery_rate);
}

void Connection::Stats(evbuffer *evb) const {
  quiche_stats stats;
  quiche_conn_stats(conn_, &stats);
  auto *end = fmt::format_to(udp_buffer,
                             "connection {:spn} recv={} sent={} lost={} "
                             "rtt={}ns cwnd={} dilivery_rate={}bytes/s\n",
                             HexId(), stats.recv, stats.sent, stats.lost,
                             stats.rtt, stats.cwnd, stats.delivery_rate);
  evbuffer_add(evb, udp_buffer, end - udp_buffer);
}

ssize_t Connection::Send(StreamId stream_id, const uint8_t *buf, size_t buf_len,
                         bool fin) {
  auto r = quiche_conn_stream_send(conn_, stream_id, buf, buf_len, fin);
  if (r < 0) {
    logger->error("failed to send stream {}, cid {:spn}, error {}", stream_id,
                  HexId(), r);
    return -1;
  }

  logger->trace("stream {} sent {} bytes, cid {:spn}", stream_id, r, HexId());
  if (r > 0 || fin) {
    if (FlushEgress() != 0) {
      return -1;
    }
  }
  return r;
}

void Connection::ReportWritableStreams() {
  bool report_writable_streams = std::any_of(
      callbacks_.cbegin(), callbacks_.cend(),
      [](const auto *callbacks) { return callbacks->ReportWritableStreams(); });
  if (!report_writable_streams) {
    return;
  }

  auto stream_iter = quiche_conn_writable(conn_);
  for (StreamId stream_id; quiche_stream_iter_next(stream_iter, &stream_id);) {
    logger->trace("stream {} is writable, cid {:spn}", stream_id, HexId());
    for (auto *callbacks : callbacks_) {
      if (callbacks->ReportWritableStreams()) {
        callbacks->OnStreamWrite(stream_id);
      }
    }
  }
  quiche_stream_iter_free(stream_iter);
}

}  // namespace quic_tunnel
