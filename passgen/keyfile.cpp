#include "keyfile.h"

#include <keywright/platform.h>
#include <keywright/secrets.h>

#include <sodium.h>

#include <span>
#include <stdexcept>

namespace kwr {

    void keymake(const std::string& path) {
        if (sodium_init() < 0)
            throw std::runtime_error("cannot initialize libsodium");

        secret_buffer key(KEY_BYTES);
        key.resize(KEY_BYTES);
        randombytes_buf(key.data(), KEY_BYTES);

        const auto* p = reinterpret_cast<const std::byte*>(key.data());
        newfile(path, std::span<const std::byte>(p, KEY_BYTES));
    }

}
