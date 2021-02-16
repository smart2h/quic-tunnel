#ifndef QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_
#define QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_

#include <event2/bufferevent.h>

#include <map>
#include <set>

#include "non_copyable.h"
#include "quic/connection.h"

namespace quic_tunnel {

class TcpTunnelCallbacks : public ConnectionCallbacks, NonCopyable {
 protected:
  static void ReadCallback(bufferevent *bev, void *ctx);
  static void WriteCallback(bufferevent *bev, void *ctx);
  static void EventCallback(bufferevent *bev, short what, void *ctx);

  virtual bool IsEstablished() = 0;
  virtual Connection &connection() = 0;
  virtual void OnQuicConnectionClosed() = 0;
  virtual bufferevent *OnNewStream(StreamId) = 0;

  enum class Status { kReady, kUnready, kClosed };
  virtual Status OnTcpRead() = 0;

  void NewStream(StreamId stream_id, bufferevent *bev);
  void FlushTcpToQuic();

  [[nodiscard]] auto StreamNum() const noexcept {
    return stream_id_to_bev_.size();
  }

 private:
  void OnClosed() final;
  void OnStreamRead(StreamId stream_id, const uint8_t *buf, size_t len,
                    bool finished) final;
  void OnStreamWrite(StreamId) final;
  bool ReportWritableStreams() final { return !unwritable_streams_.empty(); }

  [[nodiscard]] auto HexId();
  bufferevent *CloseStream(StreamId stream_id);
  StreamId CloseBufferEvent(bufferevent *bev);
  void Close(bufferevent *bev);
  void CloseOnTcpWriteFinished(bufferevent *);
  void CloseOnStreamWriteFinished(bufferevent *bev);

  std::map<StreamId, bufferevent *> stream_id_to_bev_;
  std::map<bufferevent *, StreamId> bev_to_stream_id_;
  std::set<StreamId> unwritable_streams_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_
