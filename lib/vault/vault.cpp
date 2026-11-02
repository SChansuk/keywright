#include "internal.h"

#include <sodium.h>

#include <algorithm>
#include <array>

namespace kwr {
    namespace {

        constexpr std::size_t HEAD = V_SALT + V_NONCE + V_HDR;
        constexpr std::size_t TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES;

        struct kp {
            std::uint8_t ops;
            std::uint8_t mem;
        };

        kp params(vkdf k) {
            return k == vkdf::sensitive ? kp{ 4, 20 } : kp{ 3, 18 };
        }

    }

    std::vector<std::byte> vseal(const vdata& d,
        std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        vkdf kdf) {
        vready();
        std::uint8_t b = 0;
        const secret_buffer pt = vpack(d, b);
        const kp k = params(kdf);

        // salt | nonce | plain header, the same bytes that are authenticated
        std::array<std::byte, HEAD> ad{};
        randombytes_buf(ad.data(), V_SALT + V_NONCE);
        ad[V_SALT + V_NONCE + 0] = static_cast<std::byte>(V_VERSION);
        ad[V_SALT + V_NONCE + 1] = static_cast<std::byte>(k.ops);
        ad[V_SALT + V_NONCE + 2] = static_cast<std::byte>(k.mem);
        ad[V_SALT + V_NONCE + 3] = static_cast<std::byte>(b);

        const std::span<const std::byte> adv(ad);
        const secret_buffer key = vkey(pass, keyfile, adv.first(V_SALT), k.ops, k.mem);
        const secret_buffer mask = vhash(16, adv.first(V_SALT + V_NONCE));

        std::vector<std::byte> out(HEAD + pt.size() + TAG);
        std::copy_n(ad.begin(), V_SALT + V_NONCE, out.begin());
        for (std::size_t i = 0; i < V_HDR; ++i) {
            out[V_SALT + V_NONCE + i] = ad[V_SALT + V_NONCE + i] ^ mask.data()[i];
        }

        unsigned long long clen = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(out.data() + HEAD), &clen,
            reinterpret_cast<const unsigned char*>(pt.data()), pt.size(),
            reinterpret_cast<const unsigned char*>(ad.data()), ad.size(),
            nullptr,
            reinterpret_cast<const unsigned char*>(ad.data() + V_SALT),
            reinterpret_cast<const unsigned char*>(key.data()));
        return out;
    }

    vdata vopen(std::span<const std::byte> blob,
        std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        std::string_view ns) {
        vready();
        const std::string want = vnorm(ns);

        if (blob.size() < HEAD + TAG) {
            vfail();
        }

        const secret_buffer mask = vhash(16, blob.first(V_SALT + V_NONCE));
        std::array<std::byte, HEAD> ad{};
        std::copy_n(blob.begin(), V_SALT + V_NONCE, ad.begin());
        for (std::size_t i = 0; i < V_HDR; ++i) {
            ad[V_SALT + V_NONCE + i] = blob[V_SALT + V_NONCE + i] ^ mask.data()[i];
        }

        const auto ops = std::to_integer<std::uint8_t>(ad[V_SALT + V_NONCE + 1]);
        const auto mem = std::to_integer<std::uint8_t>(ad[V_SALT + V_NONCE + 2]);
        const auto b = std::to_integer<std::uint8_t>(ad[V_SALT + V_NONCE + 3]);

        // reject hostile parameters before spending any memory on the KDF
        if (std::to_integer<std::uint8_t>(ad[V_SALT + V_NONCE]) != V_VERSION ||
            ops < 1 || ops > 16 || mem < 13 || mem > 21 || b > V_MAXB) {
            vfail();
        }
        if (blob.size() != HEAD + (std::size_t{ 1024 } << b)) {
            vfail();
        }

        const std::span<const std::byte> adv(ad);
        const secret_buffer key = vkey(pass, keyfile, adv.first(V_SALT), ops, mem);

        secret_buffer pt(vsize(b));
        pt.resize(vsize(b));
        unsigned long long plen = 0;
        const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(pt.data()), &plen, nullptr,
            reinterpret_cast<const unsigned char*>(blob.data() + HEAD), blob.size() - HEAD,
            reinterpret_cast<const unsigned char*>(ad.data()), ad.size(),
            reinterpret_cast<const unsigned char*>(ad.data() + V_SALT),
            reinterpret_cast<const unsigned char*>(key.data()));
        if (rc != 0 || plen != pt.size()) {
            vfail();
        }

        for (std::size_t i = 4; i < V_HDR; ++i) {
            if (ad[V_SALT + V_NONCE + i] != std::byte{ 0 }) {
                vfail();
            }
        }

        vdata d = vunpack(pt.bytes());
        if (d.ns != want) {
            vfail();
        }
        return d;
    }

}
