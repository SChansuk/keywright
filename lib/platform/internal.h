#pragma once

#include <filesystem>
#include <string>
#include <system_error>

namespace kwr {

    std::filesystem::path pfs(const std::string& utf8);
    std::string pstr(const std::filesystem::path& p);
    std::error_code plast();

    [[noreturn]] void pfail(const std::string& what,
        const std::string& path,
        const std::error_code& ec = {});

}
