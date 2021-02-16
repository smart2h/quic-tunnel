#ifndef QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_FACTORY_H_
#define QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_FACTORY_H_

#include <memory>

#include "quic/connection_callbacks.h"

namespace quic_tunnel {

class ConnectionCallbacksFactory {
 public:
  virtual ~ConnectionCallbacksFactory() = default;
  virtual std::unique_ptr<ConnectionCallbacks> Create() = 0;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_QUIC_CONNECTION_CALLBACKS_FACTORY_H_
