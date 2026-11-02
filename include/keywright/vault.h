#pragma once

#include <keywright/secrets.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kwr {

    /// <summary>
    /// Thrown when a vault cannot be opened. The message never says why: wrong passphrase,
    /// wrong keyfile, corruption, and wrong namespace are indistinguishable by design.
    /// </summary>
    struct vault_error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    /// <summary>Argon2id cost profile. moderate is 3 passes / 256 MiB, sensitive is 4 passes / 1 GiB.</summary>
    enum class vkdf : std::uint8_t { moderate, sensitive };

    /// <summary>One account in a namespace. old and retired are set only after a rotation.</summary>
    struct vacct {
        std::string user;
        secret_buffer pw;
        std::int64_t made = 0;
        std::optional<secret_buffer> old;
        std::int64_t retired = 0;
    };

    /// <summary>Decrypted contents of one vault file: a namespace and its accounts.</summary>
    struct vdata {
        std::string ns;
        std::vector<vacct> accts;
    };

    /// <summary>
    /// Derives the vault file name for a namespace, without extension. The name depends only
    /// on the keyfile, so it can be computed without the passphrase.
    /// </summary>
    /// <exception cref="std::invalid_argument">Keyfile under 32 bytes, or an invalid namespace.</exception>
    std::string vfname(std::span<const std::byte> keyfile, std::string_view ns);

    /// <summary>
    /// Encrypts d into a complete vault file. Namespace and usernames are NFC-normalized.
    /// The file size is padded to a fixed bucket, so it reveals only a rough account count.
    /// </summary>
    /// <exception cref="std::invalid_argument">Invalid names, duplicate usernames, empty passphrase,
    /// short keyfile, or contents too large for the biggest bucket.</exception>
    std::vector<std::byte> vseal(const vdata& d,
        std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        vkdf kdf);

    /// <summary>Decrypts a vault file and checks that it belongs to the given namespace.</summary>
    /// <exception cref="vault_error">Any failure to open.</exception>
    vdata vopen(std::span<const std::byte> blob,
        std::span<const std::byte> pass,
        std::span<const std::byte> keyfile,
        std::string_view ns);

}
