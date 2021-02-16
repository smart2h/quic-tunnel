#ifndef QUIC_TUNNEL_EVENT_TIMER_H_
#define QUIC_TUNNEL_EVENT_TIMER_H_

#include <event2/event.h>

#include "log.h"
#include "util.h"

namespace quic_tunnel {

class Timer {
 public:
  explicit Timer(event *timer) : timer_(timer) {}

  int Enable(uint64_t microseconds) {
    timeval tv{static_cast<long>(microseconds / 1000000),
               static_cast<long>(microseconds)};
    tv.tv_usec -= tv.tv_sec * 1000000;
    logger->trace("schedule timeout {}s, {}us", tv.tv_sec, tv.tv_usec);
    if (evtimer_add(timer_.get(), &tv) != 0) {
      logger->error("failed to enable timer");
      return -1;
    }
    return 0;
  }

  int Disable() {
    if (evtimer_del(timer_.get()) != 0) {
      logger->error("failed to disable timer");
      return -1;
    }
    return 0;
  }

 private:
  UniquePtr<event, event_free> timer_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_EVENT_TIMER_H_
