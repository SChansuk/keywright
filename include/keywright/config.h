#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kwr {

    /// <summary>Thrown for any problem in the config text. The message includes the line number.</summary>
    struct cfg_error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    /// <summary>
    /// Settings from config.toml. Empty strings mean "not set". symbols and no_ambiguous are optional
    /// because their defaults belong to the password generator, and an empty symbols string is a
    /// real value (it turns symbols off).
    /// </summary>
    struct cfg {
        unsigned clip_secs = 30;
        std::string keyfile;
        std::string vault_dir;
        std::string ns = "default";
        std::string kdf = "moderate";
        std::optional<std::string> symbols;
        std::optional<bool> no_ambiguous;
    };

    /// <summary>
    /// Parses config text. Keys: clipboard_timeout_seconds (1-3600), keyfile, vault_dir,
    /// default_namespace, kdf_profile ("moderate" or "sensitive"), symbols, exclude_ambiguous.
    /// Paths are used literally, with no ~ or environment variable expansion.
    /// </summary>
    /// <exception cref="kwr::cfg_error">Invalid TOML, a wrong type or value, or an unknown key.</exception>
    cfg cfgparse(std::string_view toml);

    /// <summary>Reads the config file path out of meta.toml text.</summary>
    /// <exception cref="kwr::cfg_error">Invalid TOML, a missing or wrong-typed config key, or an unknown key.</exception>
    std::string metaparse(std::string_view toml);

    /// <summary>Builds the meta.toml text that points at a config file.</summary>
    std::string metamake(const std::string& config_path);

    /// <summary>The commented template written on first setup. It parses to the defaults.</summary>
    std::string cfgtemplate();
}
