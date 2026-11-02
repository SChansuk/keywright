#include "store.h"

#include <keywright/platform.h>

#include <stdexcept>

namespace kwr {

    namespace {

        bool endsep(const std::string& p) {
            return !p.empty() && (p.back() == '/' || p.back() == '\\');
        }

    }

    std::string vpath(const std::string& save_to, std::span<const std::byte> keyfile, const std::string& ns) {
        const bool dir = endsep(save_to) || isdir(save_to);
        if (!dir) {
            return save_to;
        }
        mkdirs(save_to);
        return joinpath(save_to, vfname(keyfile, ns));
    }

    vkdf kdfmap(const std::string& name) {
        if (name == "moderate") {
            return vkdf::moderate;
        }
        if (name == "sensitive") {
            return vkdf::sensitive;
        }
        throw std::runtime_error("unknown kdf profile: " + name);
    }

}
