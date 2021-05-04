#ifndef QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_
#define QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_

#include <event2/bufferevent.h>

#include <chrono>
#include <map>
#include <set>

#include "non_copyable.h"
#include "quic/connection.h"
#include "stream_id_generator.h"

namespace quic_tunnel {

class TcpTunnelCallbacks : public ConnectionCallbacks, NonCopyable {
 protected:
  static void ReadCallback(bufferevent *bev, void *ctx);
  static void WriteCallback(bufferevent *bev, void *ctx);
  static void EventCallback(bufferevent *bev, short what, void *ctx);

  ~TcpTunnelCallbacks() override { OnClosed(); };
  bool IsEstablished() { return connection_ && connection_->IsEstablished(); };
  virtual bufferevent *OnNewStream() = 0;

  enum class Status { kReady, kUnready, kClosed };
  virtual Status OnTcpRead() = 0;

 private:
  class StreamCallbacks : NonCopyable {
   public:
    StreamCallbacks(TcpTunnelCallbacks &callbacks, StreamId stream_id,
                    bufferevent *bev);

    void OnStreamRead(const uint8_t *buf, size_t len, bool finished);
    void OnStreamWrite();
    void OnTcpRead();
    void Close();

    [[nodiscard]] auto stream_id() const noexcept { return stream_id_; }
    [[nodiscard]] const auto &host() const noexcept { return host_; }
    void set_tcp_closed() noexcept {
      tcp_closed_ = true;
      tcp_tunnel_callbacks_.connection().ShutdownRead(stream_id_);
    }

   private:
    TcpTunnelCallbacks &tcp_tunnel_callbacks_;
    const StreamId stream_id_;
    bufferevent *const bev_;
    const std::chrono::time_point<std::chrono::steady_clock> created_time_;
    std::string host_;
    size_t sent_bytes_{};
    size_t recv_bytes_{};
    bool tcp_closed_{};
  };

  Connection &connection() { return *connection_; };
  StreamCallbacks &NewStream(StreamId stream_id, bufferevent *bev);
  void OnConnected(Connection &) final;
  void OnClosed() final;
  void OnStreamRead(StreamId stream_id, const uint8_t *buf, size_t len,
                    bool finished) final;
  void OnStreamWrite(StreamId) final;
  bool ReportWritableStreams() final { return !unwritable_streams_.empty(); }

  [[nodiscard]] auto HexId();
  void Close(bufferevent *bev, bool close_bev = true);
  void CloseOnTcpWriteFinished(bufferevent *);
  void CloseOnStreamWriteFinished(bufferevent *bev);

  Connection *connection_{};
  std::map<bufferevent *, StreamCallbacks> bev_to_stream_callbacks_;
  std::map<StreamId, StreamCallbacks &> stream_id_to_stream_callbacks_;
  std::set<bufferevent *> waiting_bevs_;
  std::set<StreamId> unwritable_streams_;
  StreamIdGenerator stream_id_generator_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_
