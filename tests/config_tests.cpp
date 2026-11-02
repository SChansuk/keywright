#include <keywright/config.h>
#include <keywright/platform.h>

#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>
#include <string_view>

using namespace kwr;

namespace {

    std::string fixture() {
        const auto b = readfile(KWR_PASSGEN_TOML);
        return { reinterpret_cast<const char*>(b.data()), b.size() };
    }

    std::string error_of(std::string_view text) {
        try {
            (void)cfgparse(text);
        }
        catch (const cfg_error& e) {
            return e.what();
        }
        return {};
    }

    std::string meta_error_of(std::string_view text) {
        try {
            (void)metaparse(text);
        }
        catch (const cfg_error& e) {
            return e.what();
        }
        return {};
    }

    bool has(const std::string& s, std::string_view needle) {
        return s.find(needle) != std::string::npos;
    }

}

TEST_CASE("the fixture file parses into every field", "[config]") {
    const cfg c = cfgparse(fixture());
    CHECK(c.clip_secs == 45);
    CHECK(c.keyfile == "keys/main.key");
    CHECK(c.vault_dir == "vault");
    CHECK(c.ns == "x-twitter");
    CHECK(c.kdf == "sensitive");
    REQUIRE(c.symbols.has_value());
    CHECK(*c.symbols == "!@#$");
    REQUIRE(c.no_ambiguous.has_value());
    CHECK(*c.no_ambiguous == true);
}

TEST_CASE("empty config gives the defaults", "[config]") {
    const cfg c = cfgparse("");
    CHECK(c.clip_secs == 30);
    CHECK(c.keyfile.empty());
    CHECK(c.vault_dir.empty());
    CHECK(c.ns == "default");
    CHECK(c.kdf == "moderate");
    CHECK_FALSE(c.symbols.has_value());
    CHECK_FALSE(c.no_ambiguous.has_value());
}

TEST_CASE("a partial config keeps the other defaults", "[config]") {
    const cfg c = cfgparse(R"(vault_dir = "vault")");
    CHECK(c.vault_dir == "vault");
    CHECK(c.clip_secs == 30);
    CHECK(c.kdf == "moderate");
}

TEST_CASE("an empty symbols string is a value, not unset", "[config]") {
    const cfg c = cfgparse(R"(symbols = "")");
    REQUIRE(c.symbols.has_value());
    CHECK(c.symbols->empty());
}

TEST_CASE("the clipboard timeout accepts its boundaries", "[config]") {
    CHECK(cfgparse("clipboard_timeout_seconds = 1").clip_secs == 1);
    CHECK(cfgparse("clipboard_timeout_seconds = 3600").clip_secs == 3600);
}

TEST_CASE("comments, CRLF line endings, and Unicode values are fine", "[config]") {
    const cfg c = cfgparse("# comment\r\nkeyfile = \"a\" # trailing\r\nvault_dir = \"caf\\u00e9\"\r\n");
    CHECK(c.keyfile == "a");
    CHECK(c.vault_dir == "caf\xC3\xA9");
}

TEST_CASE("invalid values are rejected with a line number and a reason", "[config][errors]") {
    struct bad {
        const char* text;
        const char* expect;
    };
    const bad cases[] = {
        { "clipboard_timeout_seconds = 0", "config line 1: clipboard_timeout_seconds must be an integer from 1 to 3600" },
        { "clipboard_timeout_seconds = 3601", "config line 1: clipboard_timeout_seconds must be an integer from 1 to 3600" },
        { "clipboard_timeout_seconds = -5", "config line 1: clipboard_timeout_seconds must be an integer from 1 to 3600" },
        { "clipboard_timeout_seconds = \"30\"", "config line 1: clipboard_timeout_seconds must be an integer from 1 to 3600" },
        { "clipboard_timeout_seconds = 30.0", "config line 1: clipboard_timeout_seconds must be an integer from 1 to 3600" },
        { "keyfile = 5", "config line 1: keyfile must be a string" },
        { "keyfile = \"\"", "config line 1: keyfile must not be empty" },
        { "vault_dir = \"\"", "config line 1: vault_dir must not be empty" },
        { "default_namespace = \"\"", "config line 1: default_namespace must not be empty" },
        { "kdf_profile = \"fast\"", "config line 1: kdf_profile must be \"moderate\" or \"sensitive\"" },
        { "symbols = 5", "config line 1: symbols must be a string" },
        { "exclude_ambiguous = \"yes\"", "config line 1: exclude_ambiguous must be true or false" },
        { "vault_dri = \"x\"", "config line 1: unknown key 'vault_dri'" },
        { "keyfile = \"a\"\nbogus = 1", "config line 2: unknown key 'bogus'" },
    };
    for (const bad& c : cases) {
        CAPTURE(c.text);
        CHECK(error_of(c.text) == c.expect);
    }
}

TEST_CASE("tables are not allowed", "[config][errors]") {
    const std::string msg = error_of("[section]\nkey = 1");
    CHECK(has(msg, "config line 1:"));
    CHECK(has(msg, "unknown key 'section'"));
}

TEST_CASE("TOML syntax errors are reported as config errors with a line", "[config][errors]") {
    CHECK_THROWS_AS(cfgparse("keyfile ="), cfg_error);
    CHECK(has(error_of("keyfile ="), "config line 1:"));
    CHECK(has(error_of("keyfile = \"a\"\nkeyfile = \"b\""), "config line 2:"));
    CHECK(has(error_of("a = 1\nb = [1, 2\n"), "config line"));
}

TEST_CASE("the template parses to the defaults", "[config][template]") {
    const cfg c = cfgparse(cfgtemplate());
    CHECK(c.clip_secs == 30);
    CHECK(c.keyfile.empty());
    CHECK(c.vault_dir.empty());
    CHECK(c.ns == "default");
    CHECK(c.kdf == "moderate");
    CHECK_FALSE(c.symbols.has_value());
    CHECK_FALSE(c.no_ambiguous.has_value());
}

TEST_CASE("every commented line in the template is valid once uncommented", "[config][template]") {
    std::string uncommented;
    int keys = 0;
    std::istringstream in(cfgtemplate());
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("# ", 0) == 0 && line.find(" = ") != std::string::npos) {
            uncommented += line.substr(2) + "\n";
            ++keys;
        }
    }
    // one line per supported key, so a new key can't be added without documenting it here
    CHECK(keys == 7);

    const cfg c = cfgparse(uncommented);
    CHECK(c.clip_secs == 30);
    CHECK(c.keyfile == "path/to/keyfile");
    CHECK(c.vault_dir == "path/to/vault/folder");
    CHECK(c.ns == "default");
    CHECK(c.kdf == "moderate");
    CHECK(c.symbols.has_value());
    CHECK(c.no_ambiguous == false);
}

TEST_CASE("metamake and metaparse round trip awkward paths", "[config][meta]") {
    const std::string paths[] = {
        "C:\\Users\\tands\\OneDrive\\keywright\\config.toml",
        "C:\\Users\\a b\\My Documents\\config.toml",
        "D:\\it's here\\config.toml",
        "\\\\server\\share\\keywright\\config.toml",
        "/home/tands/.config/keywright/config.toml",
        "/home/caf\xC3\xA9/\xE5\xAF\x86\xE9\x92\xA5/config.toml",
        "/tmp/a\"b/config.toml",
    };
    for (const std::string& p : paths) {
        CAPTURE(p);
        CHECK(metaparse(metamake(p)) == p);
    }
}

TEST_CASE("metamake output is a short commented TOML file", "[config][meta]") {
    const std::string m = metamake("/x/config.toml");
    CHECK(m.rfind("#", 0) == 0);
    CHECK(has(m, "config = "));
    CHECK(m.back() == '\n');
}

TEST_CASE("metaparse accepts comments and CRLF", "[config][meta]") {
    CHECK(metaparse("# note\r\nconfig = \"/x/config.toml\" # trailing\r\n") == "/x/config.toml");
}

TEST_CASE("metaparse rejects bad files with a clear message", "[config][meta][errors]") {
    CHECK(meta_error_of("") == "meta: missing 'config' key");
    CHECK(meta_error_of("# only a comment") == "meta: missing 'config' key");
    CHECK(meta_error_of("cfg = \"x\"") == "meta line 1: unknown key 'cfg'");
    CHECK(meta_error_of("config = \"x\"\nextra = 1") == "meta line 2: unknown key 'extra'");
    CHECK(meta_error_of("config = 5") == "meta line 1: config must be a non-empty string");
    CHECK(meta_error_of("config = \"\"") == "meta line 1: config must be a non-empty string");
    CHECK(has(meta_error_of("config ="), "meta line 1:"));
    CHECK(has(meta_error_of("config = \"a\"\nconfig = \"b\""), "meta line 2:"));
}
