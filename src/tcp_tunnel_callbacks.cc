#include "tcp_tunnel_callbacks.h"

#include <event2/buffer.h>
#include <spdlog/fmt/bin_to_hex.h>

namespace quic_tunnel {

auto TcpTunnelCallbacks::HexId() { return spdlog::to_hex(connection().id()); }

void TcpTunnelCallbacks::OnClosed() {
  if (!bev_to_stream_id_.empty()) {
    logger->info(
        "closing {} application connections since QUIC connection {:spn} "
        "closed",
        bev_to_stream_id_.size(), HexId());
    for (auto iter = bev_to_stream_id_.cbegin();
         iter != bev_to_stream_id_.cend();) {
      auto *bev = iter->first;
      ++iter;
      CloseOnTcpWriteFinished(bev);
    }
  }
  OnQuicConnectionClosed();
}

void TcpTunnelCallbacks::OnStreamRead(StreamId stream_id, const uint8_t *buf,
                                      size_t len, bool finished) {
  bufferevent *bev;
  if (auto iter = stream_id_to_bev_.find(stream_id);
      iter == stream_id_to_bev_.end()) {
    if (finished && len == 0) {
      logger->debug(
          "closed stream {} recv 0-byte fin frame, ignore it, cid {:spn}",
          stream_id, HexId());
      return;
    }

    bev = OnNewStream(stream_id);
    if (!bev) {
      connection().Close(stream_id);
      return;
    }
  } else {
    bev = iter->second;
  }

  if (len > 0) {
    auto *evb = bufferevent_get_output(bev);
    // TODO if length > ... disable stream read
    if (evbuffer_add(evb, buf, len) != 0) {
      logger->error("failed to add event buffer");
      CloseOnTcpWriteFinished(bev);
    }
    logger->trace("TCP write buffer {} bytes", evbuffer_get_length(evb));
  }

  if (finished) {
    logger->info("remote close stream {}, cid {:spn}", stream_id, HexId());
    CloseOnTcpWriteFinished(bev);
  }
}

void TcpTunnelCallbacks::OnStreamWrite(StreamId stream_id) {
  if (const auto iter = unwritable_streams_.find(stream_id);
      iter == unwritable_streams_.end()) {
    return;
  } else {
    unwritable_streams_.erase(iter);
  }

  const auto iter = stream_id_to_bev_.find(stream_id);
  if (iter == stream_id_to_bev_.end()) {
    logger->warn("not found writable stream {}, cid {:spn}", stream_id,
                 HexId());
  } else {
    bufferevent_enable(iter->second, EV_READ);
    ReadCallback(iter->second, this);
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
  if (auto status = callbacks->OnTcpRead(); status == Status::kUnready) {
    return;
  } else if (status == Status::kClosed) {
    callbacks->CloseOnTcpWriteFinished(bev);
    return;
  }

  const auto iter = callbacks->bev_to_stream_id_.find(bev);
  if (iter == callbacks->bev_to_stream_id_.end()) {
    logger->info("ignore closed buffer event");
    return;
  }

  evbuffer_ptr ptr;
  evbuffer_ptr_set(evb, &ptr, 0, EVBUFFER_PTR_SET);
  evbuffer_iovec vec;
  size_t total_sent{};
  while (evbuffer_peek(evb, -1, &ptr, &vec, 1) == 1) {
    auto sent = callbacks->connection().Send(
        iter->second, static_cast<const uint8_t *>(vec.iov_base), vec.iov_len,
        false);  // TODO do not flush every time
    if (sent < 0) {
      callbacks->CloseOnTcpWriteFinished(bev);
      break;
    }

    total_sent += sent;
    if (sent < static_cast<int>(vec.iov_len)) {
      callbacks->unwritable_streams_.emplace(iter->second);
      bufferevent_disable(bev, EV_READ);
      logger->trace(
          "stream {} send buffer is full, remaining {} bytes, total unwritable "
          "streams {}",
          iter->second, length - total_sent,
          callbacks->unwritable_streams_.size());
      break;
    }

    if (evbuffer_ptr_set(evb, &ptr, vec.iov_len, EVBUFFER_PTR_ADD) != 0) {
      logger->error("evbuffer_ptr_set failed");
      break;
    }
  }
  evbuffer_drain(evb, total_sent);
  logger->trace("TCP->QUIC {} bytes, remaining {} bytes", total_sent,
                length - total_sent);
}

void TcpTunnelCallbacks::WriteCallback(bufferevent *bev, void *ctx) {
  auto *evb = bufferevent_get_output(bev);
  if (evbuffer_get_length(evb) == 0) {
    logger->debug("TCP write finished");
    static_cast<TcpTunnelCallbacks *>(ctx)->Close(bev);
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
    const auto iter = callbacks->bev_to_stream_id_.find(bev);
    logger->info("TCP connection established for stream {}, cid {:spn}",
                 iter == callbacks->bev_to_stream_id_.end() ? 0 : iter->second,
                 callbacks->HexId());
  } else {
    logger->warn("unknown events: {}", static_cast<int>(what));
  }
}

void TcpTunnelCallbacks::NewStream(StreamId stream_id, bufferevent *bev) {
  assert(stream_id_to_bev_.find(stream_id) == stream_id_to_bev_.end());
  assert(bev_to_stream_id_.find(bev) == bev_to_stream_id_.end());
  stream_id_to_bev_[stream_id] = bev;
  bev_to_stream_id_[bev] = stream_id;
  logger->info("new stream {}, total streams {}, cid {:spn}", stream_id,
               stream_id_to_bev_.size(), HexId());
}

void TcpTunnelCallbacks::FlushTcpToQuic() {
  assert(IsEstablished());
  for (const auto [bev, _] : bev_to_stream_id_) {
    ReadCallback(bev, this);
  }
}

bufferevent *TcpTunnelCallbacks::CloseStream(StreamId stream_id) {
  if (const auto iter = stream_id_to_bev_.find(stream_id);
      iter == stream_id_to_bev_.end()) {
    logger->error("not found stream {}, cid {:spn}", stream_id, HexId());
    return nullptr;
  } else {
    logger->info("close stream {}, cid {:spn}", stream_id, HexId());
    stream_id_to_bev_.erase(iter);
    if (IsEstablished()) {
      connection().Close(stream_id);
    }
    return iter->second;
  }
}

StreamId TcpTunnelCallbacks::CloseBufferEvent(bufferevent *bev) {
  bufferevent_free(bev);
  if (const auto iter = bev_to_stream_id_.find(bev);
      iter == bev_to_stream_id_.end()) {
    logger->error("not found buffer event");
    return 0;
  } else {
    logger->info("close buffer event for stream {}, cid {:spn}", iter->second,
                 HexId());
    bev_to_stream_id_.erase(iter);
    return iter->second;
  }
}

void TcpTunnelCallbacks::Close(bufferevent *bev) {
  auto stream_id = CloseBufferEvent(bev);
  if (stream_id > 0) {
    CloseStream(stream_id);
  }
}

void TcpTunnelCallbacks::CloseOnTcpWriteFinished(bufferevent *bev) {
  if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
    Close(bev);
  } else {
    bufferevent_disable(bev, EV_READ);
    bufferevent_setcb(bev, nullptr, WriteCallback, EventCallback, this);
  }
}

void TcpTunnelCallbacks::CloseOnStreamWriteFinished(bufferevent *bev) {
  ReadCallback(bev, this);
  if (evbuffer_get_length(bufferevent_get_input(bev)) > 0) {
    logger->warn("stream write unfinished");  // TODO optimize out
  }

  if (IsEstablished()) {
    const auto iter = bev_to_stream_id_.find(bev);
    assert(iter != bev_to_stream_id_.end());
    logger->info("finish stream {} since TCP connection closed", iter->second);
  }
  Close(bev);
}

}  // namespace quic_tunnel
