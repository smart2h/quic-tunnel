#ifndef QUIC_TUNNEL_QUIC_QUIC_SERVER_H_
#define QUIC_TUNNEL_QUIC_QUIC_SERVER_H_

#include <map>

#include "quic/connection.h"
#include "quic/connection_callbacks_factory.h"

namespace quic_tunnel {

class QuicServer : NonCopyable, public ConnectionCallbacks {
 public:
  QuicServer(const QuicConfig &quic_config, EventBase &base,
             ConnectionCallbacksFactory &connection_callbacks_factory);
  ~QuicServer() override { Close(); }

  int Bind();

 private:
  void OnConnected(Connection &) override {}
  void OnClosed(Connection &) override;
  void OnStreamRead(StreamId, const uint8_t *, size_t, bool) override {}
  void OnStreamWrite(StreamId) override {}
  [[nodiscard]] bool ReportWritableStreams() const override { return false; }

  static void ReadCallback(int, short, void *);
  auto Handshake(QuicHeader &header, const sockaddr_storage &peer_addr, int fd);
  void RemoveClosedConnections();
  void Close();

  const QuicConfig &quic_config_;
  EventBase &base_;
  ConnectionCallbacksFactory &connection_callbacks_factory_;
  int fd_;
  std::unique_ptr<Event> event_;
  Timer timer_;

  using ConnectionMap =
      std::map<ConnectionId, std::pair<std::unique_ptr<Connection>,
                                       std::unique_ptr<ConnectionCallbacks>>>;
  ConnectionMap connections_;
  std::list<ConnectionId> closed_connection_ids_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_QUIC_SERVER_H_
