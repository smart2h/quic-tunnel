#include "quic/quic_header.h"

#include <event2/util.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <chrono>
#include <cstring>

#include "log.h"
#include "util.h"

namespace quic_tunnel {
namespace {

auto SecondsSinceEpoch() {
  auto duration = std::chrono::system_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

size_t FillBuffer(uint8_t *buf, uint32_t ip, uint16_t port, ConnectionId scid,
                  std::optional<ConnectionId> dcid,
                  std::optional<long> seconds) {
  size_t len{};
  memcpy(buf, &ip, sizeof(ip));
  len += sizeof(ip);
  memcpy(buf + len, &port, sizeof(port));
  len += sizeof(port);
  memcpy(buf + len, scid.data(), scid.size());
  len += scid.size();

  if (dcid) {
    memcpy(buf + len, dcid->data(), dcid->size());
    len += dcid->size();
  }

  if (seconds) {
    seconds = htobe64(*seconds);
    memcpy(buf + len, &seconds.value(), sizeof(*seconds));
    len += sizeof(*seconds);
  }
  return len;
}

void LogOpensslError() {
  auto error = ERR_get_error();
  char buffer[256];
  do {
    ERR_error_string_n(error, buffer, sizeof(buffer));
    logger->error("openssl error: {}", buffer);
    error = ERR_get_error();
  } while (error != 0);
}

int AesGcmEncrypt0(const uint8_t *plaintext, int plaintext_len,
                   const uint8_t *key, uint8_t *ciphertext) {
  UniquePtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return -1;
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                         nullptr) != 1) {
    return -1;
  }

  evutil_secure_rng_get_bytes(ciphertext, kIvBytes);
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, ciphertext) != 1) {
    return -1;
  }

  int ciphertext_len = kIvBytes;
  int len;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext + ciphertext_len, &len, plaintext,
                        plaintext_len) != 1) {
    return -1;
  }
  ciphertext_len += len;

  if (EVP_EncryptFinal_ex(ctx.get(), ciphertext + ciphertext_len, &len) != 1) {
    return -1;
  }
  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kMacTagBytes,
                          ciphertext + ciphertext_len) != 1) {
    return -1;
  }
  ciphertext_len += kMacTagBytes;

  logger->debug("AES GCM encryption input {} bytes output {} bytes",
                plaintext_len, ciphertext_len);
  return ciphertext_len;
}

int AesGcmEncrypt(const uint8_t *plaintext, int plaintext_len,
                  const uint8_t *key, uint8_t *ciphertext) {
  auto r = AesGcmEncrypt0(plaintext, plaintext_len, key, ciphertext);
  if (r <= kIvBytes + kMacTagBytes) {
    logger->error("failed to encrypt");
    LogOpensslError();
    return -1;
  }
  return r;
}

int AesGcmDecrypt0(uint8_t *ciphertext, int ciphertext_len, const uint8_t *key,
                   uint8_t *plaintext) {
  UniquePtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return -1;
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                         nullptr) != 1) {
    return -1;
  }

  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, ciphertext) != 1) {
    return -1;
  }

  int plaintext_len;
  if (EVP_DecryptUpdate(ctx.get(), plaintext, &plaintext_len,
                        ciphertext + kIvBytes,
                        ciphertext_len - kIvBytes - kMacTagBytes) != 1) {
    return -1;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kMacTagBytes,
                          ciphertext + ciphertext_len - kMacTagBytes) != 1) {
    return -1;
  }

  int len;
  if (EVP_DecryptFinal_ex(ctx.get(), plaintext + plaintext_len, &len) != 1) {
    return -1;
  }
  plaintext_len += len;

  logger->debug("AES GCM decryption input {} bytes output {} bytes",
                ciphertext_len, plaintext_len);
  return plaintext_len;
}

int AesGcmDecrypt(uint8_t *ciphertext, int ciphertext_len, const uint8_t *key,
                  uint8_t *plaintext) {
  if (ciphertext_len <= kIvBytes + kMacTagBytes) {
    logger->error("invalid ciphertext");
    return -1;
  }

  auto r = AesGcmDecrypt0(ciphertext, ciphertext_len, key, plaintext);
  if (r <= 0) {
    logger->error("failed to decrypt");
    LogOpensslError();
    return -1;
  }
  return r;
}

constexpr int kKeyBytes = 16;

auto GenerateRandomKey() {
  std::array<uint8_t, kKeyBytes> key;
  evutil_secure_rng_get_bytes(key.data(), key.size());
  return key;
}

const uint8_t *GetKey() {
  static const auto key = GenerateRandomKey();
  return key.data();
}

}  // namespace

int QuicHeader::Parse(const uint8_t *buf, size_t buf_len, QuicHeader &header) {
  size_t scid_len = header.scid.size();
  size_t dcid_len = header.dcid.size();
  header.token_len = sizeof(header.token);
  int r = quiche_header_info(buf, buf_len, kConnectionIdBytes, &header.version,
                             &header.type, header.scid.data(), &scid_len,
                             header.dcid.data(), &dcid_len, header.token,
                             &header.token_len);
  assert(scid_len == header.scid.size() || scid_len == 0);
  assert(dcid_len == header.dcid.size());
  return r;
}

int QuicHeader::MintToken(const sockaddr_storage &addr) {
  uint8_t buf[kTokenBytes];
  auto *addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
  auto ip = addr_in->sin_addr.s_addr;
  auto port = addr_in->sin_port;
  auto seconds = SecondsSinceEpoch();

  token_len = FillBuffer(buf, ip, port, scid, dcid, seconds);
  auto len = AesGcmEncrypt(buf, token_len, GetKey(), token);
  if (len < 0) {
    return -1;
  }

  token_len = len;
  return 0;
}

bool QuicHeader::ValidateToken(const sockaddr_storage &addr,
                               ConnectionId &odcid) {
  if (token_len != kTokenBytes) {
    return false;
  }

  uint8_t buf[kTokenBytes];
  auto len = AesGcmDecrypt(token, token_len, GetKey(), buf);
  if (len < 0) {
    return false;
  }

  auto *addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
  auto ip = addr_in->sin_addr.s_addr;
  auto port = addr_in->sin_port;
  len = FillBuffer(token, ip, port, scid, {}, {});
  if (memcmp(buf, token, len) != 0) {
    return false;
  }

  memcpy(odcid.data(), buf + len, odcid.size());

  long seconds;
  memcpy(&seconds, buf + len + odcid.size(), sizeof(seconds));
  seconds = be64toh(seconds);
  auto now = SecondsSinceEpoch();
  if (now - seconds > 10) {
    logger->warn("token expired {}", seconds);
    return false;
  }
  return true;
}

}  // namespace quic_tunnel
