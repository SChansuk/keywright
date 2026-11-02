#pragma once

#include <keywright/secrets.h>
#include <keywright/vault.h>

#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>

namespace kwr {

    struct exit_error : std::runtime_error {
        int code;
        exit_error(int c, const std::string& m) : std::runtime_error(m), code(c) {}
    };

    std::string vpath(const std::string& save_to, std::span<const std::byte> keyfile, const std::string& ns);

    vkdf kdfmap(const std::string& name);

    /// Throws exit_error: 1 bad input, 2 account exists without force, 3 cannot open.
    void vsave(const std::string& path, const std::string& ns, const std::string& user,
        const secret_buffer& pw, std::span<const std::byte> keyfile, vkdf kdf, bool force);

}
