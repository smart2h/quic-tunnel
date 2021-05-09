#ifndef QUIC_TUNNEL_EVENT_EVENT_BASE_H_
#define QUIC_TUNNEL_EVENT_EVENT_BASE_H_

#include <event2/event.h>

#include "event/event.h"
#include "event/timer.h"

namespace quic_tunnel {

class EventBase {
 public:
  EventBase() : base_(event_base_new()) {
    if (!base_) {
      logger->error("failed to create event base");
      throw std::runtime_error("failed to create event base");
    }
  }

  event_base *base() { return base_.get(); }

  std::unique_ptr<Event> NewEvent(evutil_socket_t fd, short what,
                                  event_callback_fn cb, void *arg) {
    auto ev = event_new(base_.get(), fd, what, cb, arg);
    if (!ev) {
      logger->error("failed to create event");
      throw std::runtime_error("failed to create event");
    }
    return std::make_unique<Event>(ev);
  }

  Timer NewTimer(event_callback_fn cb, void *arg) {
    auto timer = evtimer_new(base_.get(), cb, arg);
    if (!timer) {
      logger->error("failed to create timer");
      throw std::runtime_error("failed to create timer");
    }
    return Timer(timer);
  }

  int Dispatch() {
    if (event_base_dispatch(base_.get()) != 0) {
      logger->error("failed to dispatch");
      return -1;
    }
    return 0;
  }

  int Exit() {
    if (event_base_loopexit(base_.get(), nullptr) != 0) {
      logger->error("failed to exit event loop");
      return -1;
    }
    return 0;
  }

 private:
  UniquePtr<event_base, event_base_free> base_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_EVENT_EVENT_BASE_H_
