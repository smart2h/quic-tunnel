#ifndef QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_H_
#define QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_H_

namespace quic_tunnel {

using StreamId = uint64_t;
class Connection;

class ConnectionCallbacks {
 public:
  virtual ~ConnectionCallbacks() = default;
  virtual void OnConnected(Connection &) = 0;
  virtual void OnClosed(Connection &) = 0;
  virtual void OnStreamRead(StreamId, const uint8_t *, size_t, bool) = 0;
  virtual void OnStreamWrite(StreamId) = 0;
  [[nodiscard]] virtual bool ReportWritableStreams() const = 0;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_H_
