#ifndef QUIC_TUNNEL_EVENT_EVENT_H_
#define QUIC_TUNNEL_EVENT_EVENT_H_

#include <event2/event.h>

#include "log.h"
#include "util.h"

namespace quic_tunnel {

class Event {
 public:
  explicit Event(event *ev) : ev_(ev) {}

  int Enable() {
    if (event_add(ev_.get(), nullptr) != 0) {
      logger->error("failed to enable event");
      return -1;
    }
    return 0;
  }

  int Disable() {
    if (event_del(ev_.get()) != 0) {
      logger->error("failed to disable event");
      return -1;
    }
    return 0;
  }

 private:
  UniquePtr<event, event_free> ev_;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_EVENT_EVENT_H_
