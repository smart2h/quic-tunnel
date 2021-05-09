cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILER clang++)

project(quic-tunnel)

find_package(toml11 3.6.0 REQUIRED)

add_executable(
  quic-tunnel
  src/admin.cc
  src/admin.h
  src/app_config.cc
  src/app_config.h
  src/event/event.h
  src/event/event_base.h
  src/event/timer.h
  src/log.cc
  src/log.h
  src/main.cc
  src/non_copyable.h
  src/quic/connection.cc
  src/quic/connection.h
  src/quic/connection_callbacks.h
  src/quic/connection_callbacks_factory.h
  src/quic/quic_client.cc
  src/quic/quic_client.h
  src/quic/quic_config.cc
  src/quic/quic_config.h
  src/quic/quic_header.cc
  src/quic/quic_header.h
  src/quic/quic_server.cc
  src/quic/quic_server.h
  src/stream_id_generator.h
  src/tcp_tunnel_callbacks.cc
  src/tcp_tunnel_callbacks.h
  src/tcp_tunnel_client.cc
  src/tcp_tunnel_client.h
  src/tcp_tunnel_server.cc
  src/tcp_tunnel_server.h
  src/util.cc
  src/util.h)

target_include_directories(quic-tunnel PRIVATE src)

target_compile_options(quic-tunnel PRIVATE -Wall -Wextra -pedantic -Weffc++
                                           -Werror)

target_link_options(quic-tunnel PRIVATE -fuse-ld=lld -L/usr/local/lib)

target_link_libraries(quic-tunnel quiche event_extra event_core pthread dl)
