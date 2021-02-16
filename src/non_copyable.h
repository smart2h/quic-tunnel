#ifndef QUIC_TUNNEL_NON_COPYABLE_H_
#define QUIC_TUNNEL_NON_COPYABLE_H_

namespace quic_tunnel {

class NonCopyable {
 protected:
  NonCopyable() = default;
  ~NonCopyable() = default;
  NonCopyable(const NonCopyable &) = delete;
  NonCopyable &operator=(const NonCopyable &) = delete;
};

}  // namespace quic_tunnel

#endif  // QUIC_TUNNEL_NON_COPYABLE_H_
