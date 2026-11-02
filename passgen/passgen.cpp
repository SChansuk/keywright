#include "passgen.h"
#include "credgen.h"
#include "setup.h"
#include "keyfile.h"
#include "store.h"

#include <keywright/platform.h>

#include <CLI/CLI.hpp>

#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace {

    std::optional<std::string> validate(const kwr::options& o) {
        const bool gen = !o.get && !o.list;
        if (gen && (o.user.empty() || o.min_len == 0)) {
            return "--user and --min-length are required";
        }
        if (o.get && o.user.empty()) {
            return "--get requires --user";
        }
        return std::nullopt;
    }

    std::string asdir(std::string p) {
        if (!p.empty() && p.back() != '/' && p.back() == '\\') {
            p.push_back('/');
        }
        return p;
    }

    void merge(kwr::options& o, const kwr::cfg& c) {
        if (o.ns.empty()) {
            o.ns = c.ns;
        }
        if (o.keyfile.empty()) {
            o.keyfile = c.keyfile;
        }
        if (o.save_to.empty() && !o.no_save) {
            o.save_to = asdir(c.vault_dir);
        }
        if (o.clip_timeout == 0) {
            o.clip_timeout = c.clip_secs;
        }
    }

    kwr::pwpol policy(const kwr::cfg& c) {
        kwr::pwpol p;
        if (c.symbols) {
            p.symbols = *c.symbols;
        }
        if (c.no_ambiguous) {
            p.no_ambiguous = *c.no_ambiguous;
        }
        return p;
    }

    void save(const kwr::options& o, const kwr::cfg& c, const kwr::secret_buffer& pw) {
        if (o.keyfile.empty()) {
            throw kwr::exit_error(1, "a keyfile is required to save via --keyfile or the config");
        }
        const auto key = kwr::readkey(o.keyfile);
        const std::string path = kwr::vpath(o.save_to, key.bytes(), o.ns);
        kwr::vsave(path, o.ns, o.user, pw, key.bytes(), kwr::kdfmap(c.kdf), o.force);
        std::fprintf(stderr, "saved to %s\n", path.c_str());
    }

    int generate(const kwr::options& o, const kwr::cfg& c) {
        try {
            const auto pw = kwr::pwgen(policy(c), o.min_len);
            if (!o.save_to.empty()) {
                try {
                    save(o, c, pw);
                }
                catch (const kwr::exit_error& e) {
                    std::fprintf(stderr, "%s\n", e.what());
                    return e.code;
                }
                catch (const std::exception& e) {
                    std::fprintf(stderr, "%s\n", e.what());
                    return 4;
                }
            }
            if (o.print) {
                std::fwrite(pw.data(), 1, pw.size(), stdout);
                std::fputc('\n', stdout);
            }
            else {
                std::fprintf(stderr, "copied to the clipboard, clearing in %u seconds (Ctrl-C clears now)\n",
                    o.clip_timeout);
                kwr::cliphold(pw.bytes(), o.clip_timeout);
            }
        }
        catch (const std::exception& e) {
            std::fprintf(stderr, "%s\n", e.what());
            return 1;
        }
        return 0;
    }

    int makekey(const std::string& path) {
        if (kwr::isfile(path)) {
            std::fprintf(stderr, "%s already exists\n", path.c_str());
            return 2;
        }
        try {
            kwr::keymake(path);
        }
        catch (const std::exception& e) {
            std::fprintf(stderr, "%s\n", e.what());
            return 4;
        }
        std::fprintf(stderr, "keyfile created: %s\nkeep it away from your vault files\n", path.c_str());
        return 0;
    }

    int run(const std::vector<std::string>& args) {
        kwr::options o;

        CLI::App app{ "kwrpassgen" };
        app.add_option("--ns", o.ns, "namespace");
        auto* user = app.add_option("--user", o.user, "account name");
        auto* len = app.add_option("--min-length", o.min_len, "minimum password length")
            ->check(CLI::Range(kwr::PW_MINLEN, kwr::PW_MAXLEN));
        auto* save_to = app.add_option("--save-to", o.save_to, "vault directory or file");
        app.add_option("--keyfile", o.keyfile, "keyfile path");
        app.add_option("--clip-timeout", o.clip_timeout, "clipboard clear timeout in seconds")
            ->check(CLI::PositiveNumber);

        auto* get = app.add_flag("--get", o.get, "retrieve a stored password");
        auto* list = app.add_flag("--list", o.list, "list usernames in a namespace");
        auto* mk = app.add_option("--make-keyfile", o.make_keyfile, "create a keyfile and exit");
        auto* force = app.add_flag("--force", o.force, "rotate an existing account");
        auto* no_save = app.add_flag("--no-save", o.no_save, "generate only");
        auto* previous = app.add_flag("--previous", o.previous, "with --get: history password");
        app.add_flag("--print", o.print, "write to stdout instead of the clipboard");

        get->excludes(list)->excludes(mk);
        list->excludes(mk);
        len->excludes(get)->excludes(list)->excludes(mk);
        force->excludes(get)->excludes(list)->excludes(mk);
        no_save->excludes(save_to);
        previous->needs(get);
        user->excludes(list);

        std::vector<const char*> argv;
        for (const auto& a : args) {
            argv.push_back(a.c_str());
        }

        try {
            app.parse(static_cast<int>(argv.size()), argv.data());
        }
        catch (const CLI::ParseError& e) {
            app.exit(e);
            return e.get_exit_code() == 0 ? 0 : 1;
        }

        if (!o.make_keyfile.empty()) {
            return makekey(o.make_keyfile);
        }

        kwr::cfg c;
        try {
            c = kwr::cfgopen();
        }
        catch (const std::exception& e) {
            std::fprintf(stderr, "%s\n", e.what());
            return 1;
        }
        merge(o, c);

        if (const auto err = validate(o)) {
            std::fprintf(stderr, "%s\n", err->c_str());
            return 1;
        }

        if (!o.get && !o.list) {
            return generate(o, c);
        }
        std::fputs("not implemented yet\n", stderr);
        return 1;
    }

#if defined(_WIN32)

    struct utf8console {
        UINT old = ::GetConsoleOutputCP();
        utf8console() { ::SetConsoleOutputCP(CP_UTF8); }
        ~utf8console() { ::SetConsoleOutputCP(old); }
    };

    std::string utf8(const wchar_t* w) {
        const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 1 ? static_cast<std::size_t>(n) - 1 : 0, '\0');
        if (n > 1) {
            ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
        }
        return s;
    }

#endif

}

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv) {
    const utf8console cp;
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        args.push_back(utf8(argv[i]));
    }
    return run(args);
}
#else
int main(int argc, char** argv) {
    return run(std::vector<std::string>(argv, argv + argc));
}
#endif
