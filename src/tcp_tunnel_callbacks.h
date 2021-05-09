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

class Admin;
class TcpTunnelCallbacks : public ConnectionCallbacks, NonCopyable {
 public:
  ~TcpTunnelCallbacks() override;
  void Stats(evbuffer *) const;
  void Close();

 protected:
  static void ReadCallback(bufferevent *bev, void *ctx);
  static void WriteCallback(bufferevent *bev, void *ctx);
  static void EventCallback(bufferevent *bev, short what, void *ctx);

  explicit TcpTunnelCallbacks(Admin &admin);
  virtual bufferevent *OnNewStream() = 0;

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
    [[nodiscard]] int DurationSeconds() const noexcept;
    [[nodiscard]] const auto &host() const noexcept { return host_; }
    [[nodiscard]] auto sent_bytes() const noexcept { return sent_bytes_; }
    [[nodiscard]] auto recv_bytes() const noexcept { return recv_bytes_; }
    void set_tcp_closed() noexcept {
      tcp_closed_ = true;
      tcp_tunnel_callbacks_.connection().ShutdownRead(stream_id_);
    }

   private:
    void LogStats(bool remote_closed) const;

    TcpTunnelCallbacks &tcp_tunnel_callbacks_;
    const StreamId stream_id_;
    bufferevent *const bev_;
    const std::chrono::time_point<std::chrono::steady_clock> created_time_;
    std::string host_;
    size_t sent_bytes_{};
    size_t recv_bytes_{};
    bool tcp_closed_{};
    bool closed_{};
  };

  Connection &connection() { return *connection_; };
  [[nodiscard]] bool IsEstablished() const {
    return connection_ && connection_->IsEstablished();
  };
  StreamCallbacks &NewStream(StreamId stream_id, bufferevent *bev);
  void OnConnected(Connection &) final;
  void OnClosed();
  void OnClosed(Connection &) final { OnClosed(); }
  void OnStreamRead(StreamId stream_id, const uint8_t *buf, size_t len,
                    bool finished) final;
  void OnStreamWrite(StreamId) final;
  [[nodiscard]] bool ReportWritableStreams() const final {
    return !unwritable_streams_.empty();
  }
  void CloseStreams();

  [[nodiscard]] auto HexId();
  void Close(bufferevent *bev, bool close_bev = true);
  void CloseOnTcpWriteFinished(bufferevent *);
  void CloseOnStreamWriteFinished(bufferevent *bev);

  Admin &admin_;
  Connection *connection_{};
  std::map<bufferevent *, StreamCallbacks> bev_to_stream_callbacks_;
  std::map<StreamId, StreamCallbacks &> stream_id_to_stream_callbacks_;
  std::set<StreamId> unwritable_streams_;
  StreamIdGenerator stream_id_generator_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_TCP_TUNNEL_CALLBACKS_H_
