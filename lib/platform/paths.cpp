#include "internal.h"

#include <keywright/platform.h>

#include <cerrno>
#include <cstdlib>
#include <stdexcept>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>
#endif

namespace kwr {

    std::filesystem::path pfs(const std::string& utf8) {
        return std::filesystem::path(
            std::u8string(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size()));
    }

    std::string pstr(const std::filesystem::path& p) {
        const std::u8string u = p.u8string();
        return { reinterpret_cast<const char*>(u.data()), u.size() };
    }

    std::error_code plast() {
#if defined(_WIN32)
        return { static_cast<int>(::GetLastError()), std::system_category() };
#else
        return { errno, std::system_category() };
#endif
    }

    void pfail(const std::string& what, const std::string& path, const std::error_code& ec) {
        std::string msg = what + ": " + path;
        if (ec) {
            msg += " (" + ec.message() + ")";
        }
        throw std::runtime_error(msg);
    }

    std::string cfgdir() {
#if defined(_WIN32)
        PWSTR w = nullptr;
        const HRESULT hr = ::SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, nullptr, &w);
        if (FAILED(hr)) {
            ::CoTaskMemFree(w);
            throw std::runtime_error("cannot locate the config folder");
        }
        const std::filesystem::path p = std::filesystem::path(w) / L"keywright";
        ::CoTaskMemFree(w);
        return pstr(p);
#else
        const char* home = std::getenv("HOME");
#if defined(__APPLE__)
        if (home == nullptr || *home == '\0') {
            throw std::runtime_error("cannot locate the config folder");
        }
        return pstr(std::filesystem::path(home) / "Library" / "Application Support" / "keywright");
#else
        const char* xdg = std::getenv("XDG_CONFIG_HOME");
        // the XDG spec says to ignore an empty or relative value
        if (xdg != nullptr && xdg[0] == '/') {
            return pstr(std::filesystem::path(xdg) / "keywright");
        }
        if (home == nullptr || *home == '\0') {
            throw std::runtime_error("cannot locate the config folder");
        }
        return pstr(std::filesystem::path(home) / ".config" / "keywright");
#endif
#endif
    }

    std::string joinpath(const std::string& dir, const std::string& name) {
        return pstr(pfs(dir) / pfs(name));
    }

    bool isfile(const std::string& path) {
        std::error_code ec;
        return std::filesystem::is_regular_file(pfs(path), ec);
    }

    bool isdir(const std::string& path) {
        std::error_code ec;
        return std::filesystem::is_directory(pfs(path), ec);
    }

    void mkdirs(const std::string& path) {
        std::error_code ec;
        std::filesystem::create_directories(pfs(path), ec);
        if (ec || !isdir(path)) {
            pfail("cannot create folder", path, ec);
        }
    }

    std::string abspath(const std::string& path) {
        if (path.empty()) {
            pfail("empty path", path);
        }
        std::error_code ec;
        const std::filesystem::path p = std::filesystem::absolute(pfs(path), ec);
        if (ec) {
            pfail("cannot resolve", path, ec);
        }
        return pstr(p.lexically_normal());
    }

    std::string parentdir(const std::string& path) {
        return pstr(pfs(path).parent_path());
    }

    bool isabs(const std::string& path) {
        return pfs(path).is_absolute();
    }

}
