# quic-tunnel

Establish a tunnel over `QUIC`.

Only `TCP` is supported now.

# Build on Ubuntu 20.04

## Install dependencies using package manager

```shell
sudo apt install cmake clang libevent-dev libssl-dev libspdlog-dev
```

## Build `quiche`

Follow the [instructions](https://github.com/cloudflare/quiche#building), build
`quiche` with `ffi` enabled:

```shell
cargo build --release --features ffi
sudo cp include/quiche.h /usr/local/include
sudo cp target/release/libquiche.a /usr/local/lib
```

## Build `toml11`

```shell
git clone https://github.com/ToruNiina/toml11.git
cd toml11
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

## Build `quic-tunnel`

```shell
git clone https://github.com/smart2h/quic-tunnel.git
cd quic-tunnel
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

# Usage

## Server side

Generate a certificate and a private key using `OpenSSL`. Put their path to
`cert_chain_path` and `private_key_path` in [server.toml](conf/server.toml).
And make sure the `peer_ip` and `peer_port` match the address of the target
service.

Then run:
```shell
./quic-tunnel -c ../conf/server.toml
```

## Client side

Modify [client.toml](conf/client.toml), make sure the `peer_ip` and `peer_port`
match the `bind_ip` and `bind_port` in [server.toml](conf/server.toml).

Then run:
```shell
./quic-tunnel -c ../conf/client.toml
```
