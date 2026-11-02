#include "internal.h"

#include <keywright/platform.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <random>
#include <stdexcept>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kwr {
    namespace {

        constexpr std::uintmax_t MAXKEY = 1024 * 1024;

        std::filesystem::path tmppath(const std::filesystem::path& target) {
            std::random_device rd;
            char hex[17];
            std::snprintf(hex, sizeof hex, "%08x%08x", rd(), rd());
            std::filesystem::path p = target;
            p += ".";
            p += hex;
            p += ".tmp";
            return p;
        }

        std::uintmax_t fsize(const std::string& path) {
            std::error_code ec;
            const std::uintmax_t n = std::filesystem::file_size(pfs(path), ec);
            if (ec) {
                pfail("cannot read", path, ec);
            }
            return n;
        }

        void readinto(const std::string& path, std::byte* dst, std::size_t n) {
            std::ifstream f(pfs(path), std::ios::binary);
            if (!f) {
                pfail("cannot open", path, plast());
            }
            f.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
            if (static_cast<std::size_t>(f.gcount()) != n) {
                pfail("cannot read", path);
            }
        }

#if defined(_WIN32)

        HANDLE create_private(const std::filesystem::path& p) {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;OW)", SDDL_REVISION_1, &sd, nullptr)) {
                pfail("cannot build owner-only permissions for", pstr(p), plast());
            }
            SECURITY_ATTRIBUTES sa{ sizeof sa, sd, FALSE };
            HANDLE h = ::CreateFileW(p.c_str(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            const DWORD err = ::GetLastError();
            ::LocalFree(sd);
            ::SetLastError(err);
            return h;
        }

        void save(const std::string& path, std::span<const std::byte> data, bool replace) {
            const std::filesystem::path target = pfs(path);
            const std::filesystem::path dst = replace ? tmppath(target) : target;

            HANDLE h = create_private(dst);
            if (h == INVALID_HANDLE_VALUE) {
                pfail("cannot create", path, plast());
            }

            std::error_code err;
            const std::byte* p = data.data();
            std::size_t left = data.size();
            while (left > 0 && !err) {
                const DWORD n = static_cast<DWORD>(std::min<std::size_t>(left, std::size_t{ 1 } << 20));
                DWORD wrote = 0;
                if (!::WriteFile(h, p, n, &wrote, nullptr)) {
                    err = plast();
                }
                else if (wrote == 0) {
                    err = std::make_error_code(std::errc::io_error);
                }
                p += wrote;
                left -= wrote;
            }
            if (!err && !::FlushFileBuffers(h)) {
                err = plast();
            }
            ::CloseHandle(h);

            if (!err && replace &&
                !::MoveFileExW(dst.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                err = plast();
            }
            if (err) {
                ::DeleteFileW(dst.c_str());
                pfail("cannot write", path, err);
            }
        }

#else

        void save(const std::string& path, std::span<const std::byte> data, bool replace) {
            const std::filesystem::path target = pfs(path);
            const std::filesystem::path dst = replace ? tmppath(target) : target;

            const int fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0) {
                pfail("cannot create", path, plast());
            }

            std::error_code err;
            const std::byte* p = data.data();
            std::size_t left = data.size();
            while (left > 0 && !err) {
                const ssize_t n = ::write(fd, p, left);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    err = plast();
                    break;
                }
                p += n;
                left -= static_cast<std::size_t>(n);
            }
            if (!err && ::fsync(fd) != 0) {
                err = plast();
            }
            ::close(fd);

            if (!err && replace) {
                if (::rename(dst.c_str(), target.c_str()) != 0) {
                    err = plast();
                }
                else {
                    const std::filesystem::path dir =
                        target.has_parent_path() ? target.parent_path() : std::filesystem::path(".");
                    const int dfd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC);
                    if (dfd >= 0) {
                        (void)::fsync(dfd);
                        ::close(dfd);
                    }
                }
            }
            if (err) {
                (void)::unlink(dst.c_str());
                pfail("cannot write", path, err);
            }
        }

#endif

    }

    std::vector<std::byte> readfile(const std::string& path) {
        std::vector<std::byte> out(static_cast<std::size_t>(fsize(path)));
        readinto(path, out.data(), out.size());
        return out;
    }

    secret_buffer readkey(const std::string& path) {
        const std::uintmax_t n = fsize(path);
        if (n > MAXKEY) {
            pfail("keyfile is larger than 1 MiB", path);
        }
        secret_buffer b(static_cast<std::size_t>(n));
        b.resize(b.capacity());
        readinto(path, b.data(), b.size());
        return b;
    }

    void writefile(const std::string& path, std::span<const std::byte> data) {
        save(path, data, true);
    }

    void newfile(const std::string& path, std::span<const std::byte> data) {
        save(path, data, false);
    }

}
