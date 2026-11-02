#include <keywright/platform.h>

#include <stdexcept>
#include <string>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace kwr {
    namespace {

        constexpr std::size_t MAXB = 1023;

        [[noreturn]] void too_long() {
            throw std::runtime_error("input is longer than 1023 bytes");
        }

#if defined(_WIN32)

        struct hguard {
            HANDLE h;
            ~hguard() {
                if (h != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(h);
                }
            }
        };

        struct modeguard {
            HANDLE h;
            DWORD old;
            ~modeguard() {
                ::SetConsoleMode(h, old);
            }
        };

        HANDLE open_console(const wchar_t* name) {
            return ::CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
        }

        secret_buffer readtty(const std::string& prompt, bool echo) {
            // CONIN$/CONOUT$ keep this working when stdin or stdout is redirected
            const hguard in{ open_console(L"CONIN$") };
            const hguard out{ open_console(L"CONOUT$") };
            if (in.h == INVALID_HANDLE_VALUE || out.h == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("no terminal available");
            }

            DWORD mode = 0;
            if (!::GetConsoleMode(in.h, &mode)) {
                throw std::runtime_error("no terminal available");
            }
            const modeguard restore{ in.h, mode };
            if (!echo && !::SetConsoleMode(in.h, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT))) {
                throw std::runtime_error("cannot turn off terminal echo");
            }

            const int pn = ::MultiByteToWideChar(CP_UTF8, 0, prompt.data(), static_cast<int>(prompt.size()), nullptr, 0);
            std::wstring wp(static_cast<std::size_t>(pn), L'\0');
            if (pn > 0) {
                ::MultiByteToWideChar(CP_UTF8, 0, prompt.data(), static_cast<int>(prompt.size()), wp.data(), pn);
            }
            DWORD done = 0;
            ::WriteConsoleW(out.h, wp.data(), static_cast<DWORD>(wp.size()), &done, nullptr);

            // wide characters can be secret too, so they are read into a locked buffer
            secret_buffer wb((MAXB + 2) * sizeof(wchar_t));
            wb.resize(wb.capacity());
            auto* w = reinterpret_cast<wchar_t*>(wb.data());
            DWORD got = 0;
            const BOOL ok = ::ReadConsoleW(in.h, w, static_cast<DWORD>(MAXB + 2), &got, nullptr);
            ::FlushConsoleInputBuffer(in.h);
            if (!echo) {
                ::WriteConsoleW(out.h, L"\r\n", 2, &done, nullptr);
            }
            if (!ok) {
                throw std::runtime_error("cannot read from the terminal");
            }

            while (got > 0 && (w[got - 1] == L'\n' || w[got - 1] == L'\r')) {
                --got;
            }
            if (got == 0) {
                return secret_buffer(0);
            }

            const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(got), nullptr, 0, nullptr, nullptr);
            if (n <= 0 || static_cast<std::size_t>(n) > MAXB) {
                too_long();
            }
            secret_buffer res(static_cast<std::size_t>(n));
            res.resize(res.capacity());
            ::WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(got),
                reinterpret_cast<char*>(res.data()), n, nullptr, nullptr);
            return res;
        }

#else

        struct ttyguard {
            int fd;
            termios old;
            ~ttyguard() {
                ::tcsetattr(fd, TCSAFLUSH, &old);
                ::close(fd);
            }
        };

        void put(int fd, const std::string& s) {
            if (::write(fd, s.data(), s.size()) < 0) {
                // a failed prompt write is not worth aborting for
            }
        }

        secret_buffer readtty(const std::string& prompt, bool echo) {
            const int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                throw std::runtime_error("no terminal available");
            }
            termios old{};
            if (::tcgetattr(fd, &old) != 0) {
                ::close(fd);
                throw std::runtime_error("no terminal available");
            }
            const ttyguard guard{ fd, old };

            if (!echo) {
                termios quiet = old;
                quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                if (::tcsetattr(fd, TCSAFLUSH, &quiet) != 0) {
                    throw std::runtime_error("cannot turn off terminal echo");
                }
            }
            put(fd, prompt);

            secret_buffer res(MAXB);
            std::size_t len = 0;
            bool over = false;
            for (;;) {
                char c = 0;
                const ssize_t n = ::read(fd, &c, 1);
                if (n < 0 && errno == EINTR) {
                    continue;
                }
                if (n <= 0 || c == '\n') {
                    break;
                }
                if (c == '\r') {
                    continue;
                }
                if (len == MAXB) {
                    over = true;
                }
                else {
                    res.data()[len++] = static_cast<std::byte>(c);
                }
            }
            if (!echo) {
                put(fd, "\n");
            }
            if (over) {
                too_long();
            }
            res.resize(len);
            return res;
        }

#endif

    }

    secret_buffer askpass(const std::string& prompt) {
        return readtty(prompt, false);
    }

    std::string ask(const std::string& prompt) {
        const secret_buffer b = readtty(prompt, true);
        return { reinterpret_cast<const char*>(b.data()), b.size() };
    }

    bool ttyin() {
#if defined(_WIN32)
        DWORD mode = 0;
        return ::GetConsoleMode(::GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
        return ::isatty(STDIN_FILENO) != 0;
#endif
    }

}
