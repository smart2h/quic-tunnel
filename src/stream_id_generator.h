#ifndef QUIC_TUNNEL_STREAM_ID_GENERATOR_H_
#define QUIC_TUNNEL_STREAM_ID_GENERATOR_H_

#include "quic/connection_callbacks.h"

namespace quic_tunnel {

class StreamIdGenerator {
 public:
  StreamIdGenerator() : next_(0) {}

  StreamId Next() noexcept { return next_ += kMinStreamId; }

  void Reset() noexcept { next_ = 0; }

 private:
  StreamId next_;

  static inline constexpr StreamId kMinStreamId = 4;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_STREAM_ID_GENERATOR_H_
