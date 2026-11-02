#include "internal.h"

#include <utf8proc.h>

#include <cstdlib>
#include <stdexcept>

namespace kwr {
    namespace {

        constexpr char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

        std::string base32(std::span<const std::byte> in) {
            std::string out;
            std::uint32_t buf = 0;
            int bits = 0;
            for (std::byte b : in) {
                buf = (buf << 8) | static_cast<std::uint32_t>(b);
                bits += 8;
                while (bits >= 5) {
                    out.push_back(B32[(buf >> (bits - 5)) & 31]);
                    bits -= 5;
                }
            }
            if (bits > 0) {
                out.push_back(B32[(buf << (5 - bits)) & 31]);
            }
            return out;
        }

    }

    std::string vnorm(std::string_view s) {
        if (s.empty()) {
            throw std::invalid_argument("name is empty");
        }

        utf8proc_uint8_t* dst = nullptr;
        const utf8proc_ssize_t n = utf8proc_map(
            reinterpret_cast<const utf8proc_uint8_t*>(s.data()),
            static_cast<utf8proc_ssize_t>(s.size()), &dst,
            static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE));
        if (n < 0) {
            throw std::invalid_argument("name is not valid UTF-8");
        }
        std::string out(reinterpret_cast<const char*>(dst), static_cast<std::size_t>(n));
        std::free(dst);

        if (out.empty() || out.size() > 64) {
            throw std::invalid_argument("name must be 1 to 64 bytes");
        }
        for (std::size_t i = 0; i < out.size();) {
            utf8proc_int32_t cp = 0;
            const utf8proc_ssize_t len = utf8proc_iterate(
                reinterpret_cast<const utf8proc_uint8_t*>(out.data()) + i,
                static_cast<utf8proc_ssize_t>(out.size() - i), &cp);
            if (len < 0 || utf8proc_category(cp) == UTF8PROC_CATEGORY_CC) {
                throw std::invalid_argument("name contains control characters");
            }
            i += static_cast<std::size_t>(len);
        }
        return out;
    }

    std::string vfname(std::span<const std::byte> keyfile, std::string_view ns) {
        if (keyfile.size() < V_MINKF) {
            throw std::invalid_argument("keyfile too short");
        }
        const std::string name = vnorm(ns);

        const secret_buffer kf = vhash(64, keyfile);
        const secret_buffer fk = vhash(32, vbytes("kwr/filename/v1"), kf.bytes());
        const secret_buffer h = vhash(16, vbytes(name), fk.bytes());
        return base32(h.bytes());
    }

}
