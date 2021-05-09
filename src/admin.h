#ifndef QUIC_TUNNEL_ADMIN_H_
#define QUIC_TUNNEL_ADMIN_H_

#include <event2/http.h>

#include "event/event_base.h"
#include "tcp_tunnel_callbacks.h"
#include "util.h"

namespace quic_tunnel {

class Admin : NonCopyable {
 public:
  explicit Admin(EventBase &base);

  int Bind();
  void Register(TcpTunnelCallbacks &);
  void Unregister(TcpTunnelCallbacks &);

 private:
  static void StatsCallback(evhttp_request *, void *);
  static void QuitCallback(evhttp_request *, void *);

  EventBase &base_;
  UniquePtr<evhttp, evhttp_free> http_;
  std::set<TcpTunnelCallbacks *> tcp_tunnel_callbacks_set_;
  bool closing_{};
  Timer timer_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_ADMIN_H_
