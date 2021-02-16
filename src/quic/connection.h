#ifndef QUIC_TUNNEL_QUIC_CONNECTION_H_
#define QUIC_TUNNEL_QUIC_CONNECTION_H_

#include <quiche.h>

#include <memory>

#include "event/event_base.h"
#include "quic/connection_callbacks.h"
#include "quic/quic_header.h"
#include "quic_config.h"

namespace quic_tunnel {

class Connection : NonCopyable {
 public:
  Connection(const QuicConfig &quic_config, EventBase &base, int fd,
             ConnectionCallbacks &connection_callbacks,
             const sockaddr_storage &peer_addr);
  ~Connection() { Close(); }

  [[nodiscard]] bool IsClosed() const {
    return !conn_ || quiche_conn_is_closed(conn_);
  }

  [[nodiscard]] bool IsEstablished() const {
    return conn_ && quiche_conn_is_established(conn_);
  }

  [[nodiscard]] const ConnectionId &id() const noexcept { return id_; }

  int Accept(const ConnectionId &dcid, const ConnectionId &odcid,
             const ConnectionId &scid);
  int Connect();
  ssize_t Send(StreamId stream_id, const uint8_t *buf, size_t buf_len,
               bool fin);
  void Close();
  void Close(StreamId);
  int OnRead(uint8_t *buf, size_t len, size_t size);

 private:
  void OnStreamRead(StreamId stream_id, uint8_t *buf, size_t size);
  int FlushEgress();
  void OnTimeout();
  void Stats();
  void ReportWritableStreams();
  [[nodiscard]] auto HexId() const;

  const QuicConfig &quic_config_;
  bool connected_{};

  const int fd_;
  Timer timer_;
  quiche_conn *conn_;
  ConnectionCallbacks &connection_callbacks_;
  ConnectionId id_;
  const sockaddr_storage peer_addr_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_CONNECTION_H_
