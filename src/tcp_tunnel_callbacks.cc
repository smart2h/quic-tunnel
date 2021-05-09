#include "tcp_tunnel_callbacks.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <tuple>
#include <utility>

#include "admin.h"

namespace quic_tunnel {
namespace {

class HttpRequestHostParser {
 public:
  explicit HttpRequestHostParser(evbuffer *evb) : evb_(evb){};

  const char *Parse() {
    const auto max_search_length =
        std::min(evbuffer_get_length(evb_), sizeof(line_) * 2);
    evbuffer_ptr search_end;
    evbuffer_ptr_set(evb_, &search_end, 0, EVBUFFER_PTR_SET);
    evbuffer_ptr_set(evb_, &search_end, max_search_length, EVBUFFER_PTR_ADD);
    first_eol_ = evbuffer_search_range(evb_, "\n", 1, nullptr, &search_end);
    if (first_eol_.pos == -1) {
      return "";
    }

    const char *host = ParseFirstLine();
    if (strlen(host) == 0) {
      evbuffer_ptr_set(evb_, &first_eol_, 1, EVBUFFER_PTR_ADD);
      second_eol_ =
          evbuffer_search_range(evb_, "\n", 1, &first_eol_, &search_end);
      if (second_eol_.pos != -1) {
        host = ParseSecondLine();
      }
    }
    return host;
  }

 private:
  const char *ParseFirstLine() {
    const char http[] = " HTTP/";
    auto end = evbuffer_search_range(evb_, http, sizeof(http) - 1, nullptr,
                                     &first_eol_);
    if (end.pos == -1) {
      return "";
    }

    auto begin = evbuffer_search_range(evb_, " ", 1, nullptr, &end);
    if (begin.pos == -1) {
      return "";
    }

    evbuffer_ptr_set(evb_, &begin, 1, EVBUFFER_PTR_ADD);
    int len = end.pos - begin.pos;
    if (len == 0 || len >= static_cast<int>(sizeof(line_) - 1)) {
      return "";
    }

    len = evbuffer_copyout_from(evb_, &begin, line_, len);
    if (len == -1) {
      return "";
    }

    if (line_[0] == '/') {
      return "";
    }

    line_[len] = '\0';
    char *host = line_;
    while (*host == ' ') {
      ++host;
    }

    char *p = strstr(host, "://");
    if (p) {
      host = p + 3;
    }

    p = host;
    while (*p && (*p != '/' && *p != ' ')) {
      ++p;
    }
    *p = '\0';
    return host;
  }

  const char *ParseSecondLine() {
    int len = second_eol_.pos - first_eol_.pos;
    if (len == 0 || len >= static_cast<int>(sizeof(line_) - 1)) {
      return "";
    }

    len = evbuffer_copyout_from(evb_, &first_eol_, line_, len);
    if (len == -1) {
      return "";
    }

    line_[len] = '\0';
    char *host = line_;
    while (*host && *host != ':') {
      ++host;
    }

    if (*host != ':' || host - line_ < 4 ||
        strncasecmp(host - 4, "host", 4) != 0) {
      return "";
    }

    ++host;
    while (*host == ' ') {
      ++host;
    }

    char *p = host;
    while (*p && (*p != ' ' && *p != '\r')) {
      ++p;
    }
    *p = '\0';
    return host;
  }

  evbuffer *evb_;
  evbuffer_ptr first_eol_;
  evbuffer_ptr second_eol_;
  char line_[80];
};

}  // namespace

TcpTunnelCallbacks::TcpTunnelCallbacks(Admin &admin) : admin_(admin) {
  admin_.Register(*this);
}

TcpTunnelCallbacks::~TcpTunnelCallbacks() {
  admin_.Unregister(*this);
  if (IsEstablished()) {
    Close();
    OnClosed();
  }
}

auto TcpTunnelCallbacks::HexId() { return spdlog::to_hex(connection().id()); }

void TcpTunnelCallbacks::Stats(evbuffer *evb) const {
  if (!IsEstablished()) {
    return;
  }

  connection_->Stats(evb);
  evbuffer_add_printf(evb, "total streams %lu, peer streams left %lu\n",
                      bev_to_stream_callbacks_.size(),
                      connection_->PeerStreamsLeft());
  for (const auto &[_, stream] : bev_to_stream_callbacks_) {
    evbuffer_add_printf(evb,
                        "  stream: %lu\n    host: %s\n    duration: %ds\n"
                        "    recv: %luB\n    sent: %luB\n",
                        stream.stream_id(), stream.host().c_str(),
                        stream.DurationSeconds(), stream.recv_bytes(),
                        stream.sent_bytes());
  }
}

void TcpTunnelCallbacks::Close() {
  if (connection_) {
    CloseStreams();
    connection_->Close();
  }
}

void TcpTunnelCallbacks::CloseStreams() {
  if (!bev_to_stream_callbacks_.empty()) {
    logger->info(
        "closing {} application connections since QUIC connection {:spn} "
        "closing/closed",
        bev_to_stream_callbacks_.size(), HexId());
    for (auto iter = bev_to_stream_callbacks_.cbegin();
         iter != bev_to_stream_callbacks_.cend();) {
      auto *bev = iter->first;
      ++iter;
      CloseOnTcpWriteFinished(bev);
    }
  }
  unwritable_streams_.clear();
}

void TcpTunnelCallbacks::OnConnected(Connection &connection) {
  connection_ = &connection;
}

void TcpTunnelCallbacks::OnClosed() {
  CloseStreams();
  stream_id_generator_.Reset();
  connection_ = nullptr;
}

void TcpTunnelCallbacks::OnStreamRead(StreamId stream_id, const uint8_t *buf,
                                      size_t len, bool finished) {
  if (auto iter = stream_id_to_stream_callbacks_.find(stream_id);
      iter == stream_id_to_stream_callbacks_.end()) {
    if (finished && len == 0) {
      logger->error("stream {} recv 0-byte fin frame, cid {:spn}", stream_id,
                    HexId());
      connection().Close(stream_id);
      return;
    }

    auto *bev = OnNewStream();
    if (!bev) {
      connection().Close(stream_id);
    } else {
      NewStream(stream_id, bev).OnStreamRead(buf, len, finished);
    }
  } else {
    iter->second.OnStreamRead(buf, len, finished);
  }
}

void TcpTunnelCallbacks::OnStreamWrite(StreamId stream_id) {
  if (const auto iter = unwritable_streams_.find(stream_id);
      iter == unwritable_streams_.end()) {
    return;
  } else {
    unwritable_streams_.erase(iter);
  }

  if (const auto iter = stream_id_to_stream_callbacks_.find(stream_id);
      iter == stream_id_to_stream_callbacks_.end()) {
    logger->warn("not found writable stream {}, cid {:spn}", stream_id,
                 HexId());
  } else {
    iter->second.OnStreamWrite();
  }
}

void TcpTunnelCallbacks::ReadCallback(bufferevent *bev, void *ctx) {
  auto *evb = bufferevent_get_input(bev);
  const auto length = evbuffer_get_length(evb);
  logger->trace("TCP read buffer {} bytes", length);
  if (length == 0) {
    return;
  }

  auto *callbacks = static_cast<TcpTunnelCallbacks *>(ctx);
  if (const auto iter = callbacks->bev_to_stream_callbacks_.find(bev);
      iter == callbacks->bev_to_stream_callbacks_.end()) {
    if (callbacks->connection().PeerStreamsLeft() == 0) {
      logger->warn("no peer streams left");
      callbacks->Close(bev);
    } else {
      auto stream_id = callbacks->stream_id_generator_.Next();
      callbacks->NewStream(stream_id, bev).OnTcpRead();
    }
  } else {
    iter->second.OnTcpRead();
  }
}

void TcpTunnelCallbacks::WriteCallback(bufferevent *bev, void *) {
  auto *evb = bufferevent_get_output(bev);
  if (evbuffer_get_length(evb) == 0) {
    logger->debug("TCP write finished");
    bufferevent_free(bev);
  }
}

void TcpTunnelCallbacks::EventCallback(bufferevent *bev, short what,
                                       void *ctx) {
  if (what & BEV_EVENT_ERROR) {
    logger->warn("buffer event socket error: {}", strerror(errno));
  }

  auto *callbacks = static_cast<TcpTunnelCallbacks *>(ctx);
  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    callbacks->CloseOnStreamWriteFinished(bev);
  } else if (what & BEV_EVENT_CONNECTED) {
    const auto iter = callbacks->bev_to_stream_callbacks_.find(bev);
    logger->info("TCP connection established for stream {}, cid {:spn}",
                 iter == callbacks->bev_to_stream_callbacks_.end()
                     ? 0
                     : iter->second.stream_id(),
                 callbacks->HexId());
  } else {
    logger->warn("unknown events: {}", static_cast<int>(what));
  }
}

TcpTunnelCallbacks::StreamCallbacks &TcpTunnelCallbacks::NewStream(
    StreamId stream_id, bufferevent *bev) {
  assert(stream_id_to_stream_callbacks_.find(stream_id) ==
         stream_id_to_stream_callbacks_.end());
  assert(bev_to_stream_callbacks_.find(bev) == bev_to_stream_callbacks_.end());

  auto pair = bev_to_stream_callbacks_.emplace(
      std::piecewise_construct, std::forward_as_tuple(bev),
      std::forward_as_tuple(*this, stream_id, bev));
  stream_id_to_stream_callbacks_.emplace(stream_id, pair.first->second);
  const auto &host = pair.first->second.host();
  logger->info(
      "new stream {}{}{}, total streams {}, peer streams left {}, cid {:spn}",
      stream_id, host.empty() ? "" : " for ", host,
      bev_to_stream_callbacks_.size(), connection().PeerStreamsLeft(), HexId());
  return pair.first->second;
}

void TcpTunnelCallbacks::Close(bufferevent *bev, bool close_bev) {
  if (close_bev) {
    bufferevent_free(bev);
  }

  if (const auto iter = bev_to_stream_callbacks_.find(bev);
      iter == bev_to_stream_callbacks_.end()) {
    logger->info("TCP connection closed without sending data");
  } else {
    iter->second.Close();
    auto stream_id = iter->second.stream_id();
    if (const auto it = stream_id_to_stream_callbacks_.find(stream_id);
        it == stream_id_to_stream_callbacks_.end()) {
      logger->error("not found stream {}, cid {:spn}", stream_id, HexId());
    } else {
      stream_id_to_stream_callbacks_.erase(it);
    }
    bev_to_stream_callbacks_.erase(iter);
  }
}

void TcpTunnelCallbacks::CloseOnTcpWriteFinished(bufferevent *bev) {
  bool tcp_write_finished =
      evbuffer_get_length(bufferevent_get_output(bev)) == 0;
  Close(bev, tcp_write_finished);

  if (!tcp_write_finished) {
    bufferevent_disable(bev, EV_READ);
    auto *evb = bufferevent_get_input(bev);
    auto len = evbuffer_get_length(evb);
    if (len > 0) {
      evbuffer_drain(evb, len);
      logger->warn("discard TCP input {} bytes", len);
    }
    bufferevent_setcb(bev, nullptr, WriteCallback, EventCallback, this);
  }
}

void TcpTunnelCallbacks::CloseOnStreamWriteFinished(bufferevent *bev) {
  ReadCallback(bev, this);
  if (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
    if (const auto iter = bev_to_stream_callbacks_.find(bev);
        iter != bev_to_stream_callbacks_.end()) {
      iter->second.set_tcp_closed();
      auto *evb = bufferevent_get_output(bev);
      auto len = evbuffer_get_length(evb);
      if (len > 0) {
        evbuffer_drain(evb, len);
        logger->warn("discard TCP output {} bytes", len);
      }
    }
  } else {
    Close(bev);
  }
}

TcpTunnelCallbacks::StreamCallbacks::StreamCallbacks(
    TcpTunnelCallbacks &callbacks, StreamId stream_id, bufferevent *bev)
    : tcp_tunnel_callbacks_(callbacks),
      stream_id_(stream_id),
      bev_(bev),
      created_time_(std::chrono::steady_clock::now()) {
  const auto &cfg = AppConfig::GetInstance();
  if (!cfg.is_server && cfg.protocol == "http") {
    auto *evb = bufferevent_get_input(bev_);
    host_ = HttpRequestHostParser(evb).Parse();
  }
}

void TcpTunnelCallbacks::StreamCallbacks::OnStreamRead(const uint8_t *buf,
                                                       size_t len,
                                                       bool finished) {
  if (len > 0) {
    recv_bytes_ += len;
    if (tcp_closed_) {
      logger->error("TCP already closed, stream {} cid {:spn}", stream_id_,
                    tcp_tunnel_callbacks_.HexId());
    } else {
      auto *evb = bufferevent_get_output(bev_);
      // TODO if length > ... disable stream read
      if (evbuffer_add(evb, buf, len) != 0) {
        logger->error("failed to add event buffer");
        tcp_tunnel_callbacks_.CloseOnTcpWriteFinished(bev_);
      }
      logger->trace("TCP write buffer {} bytes", evbuffer_get_length(evb));
    }
  }

  if (finished) {
    closed_ = true;
    LogStats(true);
    tcp_tunnel_callbacks_.CloseOnTcpWriteFinished(bev_);
  }
}

void TcpTunnelCallbacks::StreamCallbacks::OnStreamWrite() {
  bufferevent_enable(bev_, EV_READ);
  OnTcpRead();

  if (tcp_closed_ && evbuffer_get_length(bufferevent_get_input(bev_)) == 0) {
    logger->debug("stream write finished");
    tcp_tunnel_callbacks_.Close(bev_);
  }
}

void TcpTunnelCallbacks::StreamCallbacks::OnTcpRead() {
  auto *evb = bufferevent_get_input(bev_);
  const auto length = evbuffer_get_length(evb);
  evbuffer_ptr ptr;
  evbuffer_ptr_set(evb, &ptr, 0, EVBUFFER_PTR_SET);
  evbuffer_iovec vec;
  size_t total_sent{};
  while (evbuffer_peek(evb, -1, &ptr, &vec, 1) == 1) {
    auto sent = tcp_tunnel_callbacks_.connection().Send(
        stream_id_, static_cast<const uint8_t *>(vec.iov_base), vec.iov_len,
        false);  // TODO do not flush every time
    if (sent < 0) {
      tcp_tunnel_callbacks_.CloseOnTcpWriteFinished(bev_);
      break;
    }

    total_sent += sent;
    if (sent < static_cast<int>(vec.iov_len)) {
      tcp_tunnel_callbacks_.unwritable_streams_.emplace(stream_id_);
      bufferevent_disable(bev_, EV_READ);
      logger->trace(
          "stream {} send buffer is full, remaining {} bytes, total unwritable "
          "streams {}",
          stream_id_, length - total_sent,
          tcp_tunnel_callbacks_.unwritable_streams_.size());
      break;
    }

    if (evbuffer_ptr_set(evb, &ptr, vec.iov_len, EVBUFFER_PTR_ADD) != 0) {
      logger->error("evbuffer_ptr_set failed");
      break;
    }
  }

  evbuffer_drain(evb, total_sent);
  sent_bytes_ += total_sent;
  logger->trace("TCP->QUIC {} bytes, remaining {} bytes", total_sent,
                length - total_sent);
}

void TcpTunnelCallbacks::StreamCallbacks::Close() {
  if (closed_) {
    return;
  }

  if (tcp_tunnel_callbacks_.IsEstablished()) {
    tcp_tunnel_callbacks_.connection().Close(stream_id_);
  }
  LogStats(false);
}

int TcpTunnelCallbacks::StreamCallbacks::DurationSeconds() const noexcept {
  auto duration = std::chrono::steady_clock::now() - created_time_;
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  return seconds.count();
}

void TcpTunnelCallbacks::StreamCallbacks::LogStats(bool remote_closed) const {
  logger->info(
      "{}close stream {}{}{}, lasting {} seconds, recv {} bytes, sent {} "
      "bytes, cid {:spn}",
      remote_closed ? "remote " : "", stream_id_, host_.empty() ? "" : " for ",
      host_, DurationSeconds(), recv_bytes_, sent_bytes_,
      tcp_tunnel_callbacks_.HexId());
}

}  // namespace quic_tunnel
