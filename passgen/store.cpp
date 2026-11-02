#include "store.h"

#include <keywright/platform.h>

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <optional>

namespace kwr {

    namespace {

        bool endsep(const std::string& p) {
            return !p.empty() && (p.back() == '/' || p.back() == '\\');
        }

        secret_buffer dup(const secret_buffer& s) {
            secret_buffer b(s.capacity());
            b.resize(s.size());
            std::memcpy(b.data(), s.data(), s.size());
            return b;
        }

        bool same(const secret_buffer& a, const secret_buffer& b) {
            return a.size() == b.size() && sodium_memcmp(a.data(), b.data(), a.size()) == 0;
        }

        std::int64_t now() {
            return static_cast<std::int64_t>(std::time(nullptr));
        }

        secret_buffer newpass() {
            secret_buffer p = askpass("Enter new vault passphrase: ");
            if (p.size() == 0) {
                throw exit_error(1, "passphrase must not be empty");
            }
            const secret_buffer again = askpass("Confirm passphrase: ");
            if (!same(p, again)) {
                throw exit_error(1, "passphrases do not match");
            }
            return p;
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

    void vsave(const std::string& path, const std::string& ns, const std::string& user,
        const secret_buffer& pw, std::span<const std::byte> keyfile, vkdf kdf, bool force) {
        const bool exists = isfile(path);
        const secret_buffer pass = exists ? askpass("Vault passphrase: ") : newpass();

        vdata d;
        if (exists) {
            try {
                d = vopen(readfile(path), pass.bytes(), keyfile, ns);
            }
            catch (const vault_error& e) {
                throw exit_error(3, e.what());
            }
            const auto it = std::find_if(d.accts.begin(), d.accts.end(),
                [&](const vacct& a) { return a.user == user; });
            if (it == d.accts.end()) {
                d.accts.push_back(vacct{ user, dup(pw), now(), std::nullopt, 0 });
            }
            else if (!force) {
                throw exit_error(2, "account already exists, use --force to rotate");
            }
            else {
                it->old.emplace(std::move(it->pw));
                it->pw = dup(pw);
                it->made = it->retired = now();
            }
        }
        else {
            d.ns = ns;
            d.accts.push_back(vacct{ user, dup(pw), now(), std::nullopt, 0 });
        }

        std::vector<std::byte> blob;
        try {
            blob = vseal(d, pass.bytes(), keyfile, kdf);
        }
        catch (const vault_error& e) {
            throw exit_error(1, e.what());
        }

        if (exists) {
            writefile(path, blob);
            return;
        }
        const std::string parent = parentdir(path);
        if (!parent.empty()) {
            mkdirs(parent);
        }
        newfile(path, blob);
    }

}
