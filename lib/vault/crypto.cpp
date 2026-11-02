#include "internal.h"

#include <sodium.h>

#include <stdexcept>

namespace kwr {

    void vready() {
        static const bool ok = sodium_init() >= 0;
        if (!ok) {
            throw std::runtime_error("sodium_init failed");
        }
    }

    secret_buffer vhash(std::size_t outlen,
        std::span<const std::byte> msg,
        std::span<const std::byte> key) {
        vready();
        secret_buffer out(outlen);
        out.resize(outlen);
        const int rc = crypto_generichash(
            reinterpret_cast<unsigned char*>(out.data()), outlen,
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            key.empty() ? nullptr : reinterpret_cast<const unsigned char*>(key.data()), key.size());
        if (rc != 0) {
            throw std::runtime_error("hash failed");
        }
        return out;
    }

    secret_buffer vkey(std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        std::span<const std::byte> salt,
        std::uint8_t ops,
        std::uint8_t mem) {
        if (pass.empty()) {
            throw std::invalid_argument("empty passphrase");
        }
        if (keyfile.size() < V_MINKF) {
            throw std::invalid_argument("keyfile too short");
        }
        if (salt.size() != crypto_pwhash_SALTBYTES) {
            throw std::invalid_argument("bad salt size");
        }

        const secret_buffer kf = vhash(64, keyfile);
        const secret_buffer m = vhash(64, pass, kf.bytes());

        secret_buffer master(crypto_kdf_KEYBYTES);
        master.resize(crypto_kdf_KEYBYTES);
        const std::size_t memlimit = std::size_t{ 1 } << (mem + 10);
        const int rc = crypto_pwhash(
            reinterpret_cast<unsigned char*>(master.data()), master.size(),
            reinterpret_cast<const char*>(m.data()), m.size(),
            reinterpret_cast<const unsigned char*>(salt.data()),
            ops, memlimit, crypto_pwhash_ALG_ARGON2ID13);
        if (rc != 0) {
            throw std::runtime_error("key derivation failed");
        }

        secret_buffer key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        key.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        crypto_kdf_derive_from_key(
            reinterpret_cast<unsigned char*>(key.data()), key.size(), 1, "kwrvault",
            reinterpret_cast<const unsigned char*>(master.data()));
        return key;
    }

}
