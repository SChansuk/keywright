#include "setup.h"

#include <keywright/platform.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace kwr {
    namespace {

        std::string slurp(const std::string& path) {
            const std::vector<std::byte> b = readfile(path);
            return { reinterpret_cast<const char*>(b.data()), b.size() };
        }

        std::vector<std::byte> bytes(const std::string& s) {
            const auto* p = reinterpret_cast<const std::byte*>(s.data());
            return { p, p + s.size() };
        }

        std::string trim(std::string s) {
            const auto ws = [](unsigned char c) { return std::isspace(c) != 0; };
            s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), ws));
            s.erase(std::find_if_not(s.rbegin(), s.rend(), ws).base(), s.end());
            return s;
        }

        bool is_toml(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s.size() >= 5 && s.compare(s.size() - 5, 5, ".toml") == 0;
        }

        std::string target_from(std::string in, const std::string& def) {
            in = trim(std::move(in));
            // a pasted path often arrives wrapped in quotes
            if (in.size() >= 2 && (in.front() == '"' || in.front() == '\'') && in.back() == in.front()) {
                in = trim(in.substr(1, in.size() - 2));
            }
            if (in.empty()) {
                return def;
            }
            const std::string abs = abspath(in);
            return (isdir(abs) || !is_toml(abs)) ? joinpath(abs, "config.toml") : abs;
        }

        std::string setup(const std::string& meta, const std::string& def) {
            std::fputs("No config file found.\n", stderr);
            const std::string target =
                target_from(ask("Enter file in which to save the config (" + def + "): "), def);

            mkdirs(parentdir(target));
            if (isfile(target)) {
                std::fprintf(stderr, "%s already exists, using it.\n", target.c_str());
            }
            else {
                newfile(target, bytes(cfgtemplate()));
                std::fprintf(stderr, "Created %s\n", target.c_str());
            }

            mkdirs(parentdir(meta));
            writefile(meta, bytes(metamake(target)));
            std::fprintf(stderr, "Pointer saved in %s\n", meta.c_str());
            std::fputs("Edit the config to set your keyfile and vault folder. It never holds secrets.\n", stderr);
            return target;
        }

    }

    cfg cfgopen() {
        const std::string dir = cfgdir();
        const std::string meta = joinpath(dir, "meta.toml");
        const std::string def = joinpath(dir, "config.toml");

        std::string path;
        if (isfile(meta)) {
            try {
                path = metaparse(slurp(meta));
            }
            catch (const cfg_error& e) {
                throw cfg_error(meta + ": " + e.what());
            }
            if (!isabs(path)) {
                throw cfg_error(meta + ": config must be an absolute path");
            }
            // never fall back to another file: that could silently put you on the wrong config
            if (!isfile(path)) {
                throw std::runtime_error("config file not found: " + path + "\n(set by " + meta + ")");
            }
        }
        else if (isfile(def)) {
            path = def;
        }
        else if (ttyin()) {
            path = setup(meta, def);
        }
        else {
            return cfg{};
        }

        try {
            return cfgparse(slurp(path));
        }
        catch (const cfg_error& e) {
            throw cfg_error(path + ": " + e.what());
        }
    }

}
