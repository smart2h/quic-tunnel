#ifndef QUIC_TUNNEL_QUIC_CONNECTION_H_
#define QUIC_TUNNEL_QUIC_CONNECTION_H_

#include <event2/buffer.h>
#include <quiche.h>

#include <list>
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
  ~Connection();

  [[nodiscard]] bool IsClosed() const {
    return !conn_ || quiche_conn_is_closed(conn_);
  }

  [[nodiscard]] bool IsEstablished() const {
    return conn_ && quiche_conn_is_established(conn_);
  }

  [[nodiscard]] const ConnectionId &id() const noexcept { return id_; }

  [[nodiscard]] auto PeerStreamsLeft() const noexcept {
    return quiche_conn_peer_streams_left_bidi(conn_);
  }

  void AddConnectionCallbacks(ConnectionCallbacks &callbacks);
  int Accept(const ConnectionId &dcid, const ConnectionId &odcid,
             const ConnectionId &scid);
  int Connect();
  ssize_t Send(StreamId stream_id, const uint8_t *buf, size_t buf_len,
               bool fin);
  void Close();
  void Close(StreamId);
  void ShutdownRead(StreamId);
  int OnRead(uint8_t *buf, size_t len, size_t size);
  void Stats(evbuffer *) const;

 private:
  void OnStreamRead(StreamId stream_id, uint8_t *buf, size_t size);
  void OnStreamRead(StreamId, const uint8_t *, size_t, bool);
  int FlushEgress();
  void OnTimeout();
  void OnConnected();
  void OnClosed();
  void Stats() const;
  void ReportWritableStreams();
  [[nodiscard]] auto HexId() const;

  const QuicConfig &quic_config_;
  bool connected_{};

  const int fd_;
  Timer timer_;
  quiche_conn *conn_;
  std::list<ConnectionCallbacks *> callbacks_;
  ConnectionId id_;
  const sockaddr_storage peer_addr_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_CONNECTION_H_
