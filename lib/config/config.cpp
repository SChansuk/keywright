#include <keywright/config.h>

#include <toml++/toml.hpp>

#include <cstdint>
#include <sstream>

namespace kwr {
    namespace {

        [[noreturn]] void bad(const toml::node& n, const std::string& msg, const char* who = "config") {
            throw cfg_error(std::string(who) + " line " + std::to_string(n.source().begin.line) + ": " + msg);
        }

        toml::table parse_table(std::string_view text, const char* who) {
            try {
                return toml::parse(text);
            }
            catch (const toml::parse_error& e) {
                throw cfg_error(std::string(who) + " line " + std::to_string(e.source().begin.line) + ": " +
                    std::string(e.description()));
            }
        }

        std::string str_of(const toml::node& n, std::string_view key, bool allow_empty) {
            const auto v = n.value_exact<std::string>();
            if (!v) {
                bad(n, std::string(key) + " must be a string");
            }
            if (!allow_empty && v->empty()) {
                bad(n, std::string(key) + " must not be empty");
            }
            return *v;
        }

    }

    cfg cfgparse(std::string_view text) {
        const toml::table tbl = parse_table(text, "config");

        cfg c;
        for (auto&& [k, v] : tbl) {
            const std::string_view key = k.str();
            if (key == "clipboard_timeout_seconds") {
                const auto n = v.value_exact<std::int64_t>();
                if (!n || *n < 1 || *n > 3600) {
                    bad(v, "clipboard_timeout_seconds must be an integer from 1 to 3600");
                }
                c.clip_secs = static_cast<unsigned>(*n);
            }
            else if (key == "keyfile") {
                c.keyfile = str_of(v, key, false);
            }
            else if (key == "vault_dir") {
                c.vault_dir = str_of(v, key, false);
            }
            else if (key == "default_namespace") {
                c.ns = str_of(v, key, false);
            }
            else if (key == "kdf_profile") {
                c.kdf = str_of(v, key, false);
                if (c.kdf != "moderate" && c.kdf != "sensitive") {
                    bad(v, "kdf_profile must be \"moderate\" or \"sensitive\"");
                }
            }
            else if (key == "symbols") {
                c.symbols = str_of(v, key, true);
            }
            else if (key == "exclude_ambiguous") {
                const auto b = v.value_exact<bool>();
                if (!b) {
                    bad(v, "exclude_ambiguous must be true or false");
                }
                c.no_ambiguous = *b;
            }
            else {
                bad(v, "unknown key '" + std::string(key) + "'");
            }
        }
        return c;
    }

    std::string metaparse(std::string_view text) {
        const toml::table tbl = parse_table(text, "meta");

        std::string path;
        for (auto&& [k, v] : tbl) {
            if (k.str() != "config") {
                bad(v, "unknown key '" + std::string(k.str()) + "'", "meta");
            }
            const auto s = v.value_exact<std::string>();
            if (!s || s->empty()) {
                bad(v, "config must be a non-empty string", "meta");
            }
            path = *s;
        }
        if (path.empty()) {
            throw cfg_error("meta: missing 'config' key");
        }
        return path;
    }

    std::string metamake(const std::string& config_path) {
        std::ostringstream os;
        os << "# keywright: points to the real config file\n";
        os << toml::table{ { "config", config_path } } << "\n";
        return os.str();
    }

    std::string cfgtemplate() {
        return R"(# keywright configuration. It never holds secrets.
# Uncomment a line to change it. Values shown are the defaults where one exists.

# clipboard_timeout_seconds = 30
# keyfile = "path/to/keyfile"
# vault_dir = "path/to/vault/folder"
# default_namespace = "default"
# kdf_profile = "moderate"
# symbols = "!@#$%^&*()-_=+[]{};:,.?"
# exclude_ambiguous = false
)";
    }

}
