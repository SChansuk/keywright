#pragma once

#include <keywright/secrets.h>
#include <keywright/vault.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace kwr {

    inline constexpr std::size_t V_SALT = 16;
    inline constexpr std::size_t V_NONCE = 24;
    inline constexpr std::size_t V_HDR = 8;
    inline constexpr std::size_t V_MINKF = 32;
    inline constexpr std::uint8_t V_VERSION = 1;
    inline constexpr std::uint8_t V_MAXB = 6;

    inline constexpr std::size_t vsize(unsigned b) {
        return (std::size_t{ 1024 } << b) - 16;
    }

    inline std::span<const std::byte> vbytes(std::string_view s) {
        return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
    }

    void vready();
    std::string vnorm(std::string_view s);

    secret_buffer vhash(std::size_t outlen,
        std::span<const std::byte> msg,
        std::span<const std::byte> key = {});

    secret_buffer vkey(std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        std::span<const std::byte> salt,
        std::uint8_t ops,
        std::uint8_t mem);

    secret_buffer vpack(const vdata& d, std::uint8_t& b);
    vdata vunpack(std::span<const std::byte> pt);

    [[noreturn]] inline void vfail() {
        throw vault_error("cannot open vault");
    }
}
