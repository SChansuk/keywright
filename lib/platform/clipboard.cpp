#include <keywright/platform.h>

#include <algorithm>
#include <stdexcept>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace kwr {

#if defined(_WIN32)

    namespace {

        HANDLE g_stop = nullptr;
        HANDLE g_done = nullptr;

        BOOL WINAPI on_break(DWORD type) {
            switch (type) {
            case CTRL_C_EVENT:
            case CTRL_BREAK_EVENT:
                ::SetEvent(g_stop);
                return TRUE;
            case CTRL_CLOSE_EVENT:
            case CTRL_LOGOFF_EVENT:
            case CTRL_SHUTDOWN_EVENT:
                // Windows ends the process when this returns, so give the clear a moment to finish
                ::SetEvent(g_stop);
                ::WaitForSingleObject(g_done, 4000);
                return TRUE;
            default:
                return FALSE;
            }
        }

        struct stopper {
            stopper() {
                g_stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                g_done = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (g_stop == nullptr || g_done == nullptr) {
                    release();
                    throw std::runtime_error("cannot create synchronization events");
                }
                ::SetConsoleCtrlHandler(on_break, TRUE);
            }
            ~stopper() {
                ::SetEvent(g_done);
                ::SetConsoleCtrlHandler(on_break, FALSE);
                release();
            }
            static void release() {
                if (g_stop != nullptr) {
                    ::CloseHandle(g_stop);
                    g_stop = nullptr;
                }
                if (g_done != nullptr) {
                    ::CloseHandle(g_done);
                    g_done = nullptr;
                }
            }
        };

        // a clipboard owner window is required: with a null owner SetClipboardData is allowed to fail
        struct owner {
            HWND h = ::CreateWindowExW(0, L"STATIC", L"keywright", 0, 0, 0, 0, 0, HWND_MESSAGE,
                nullptr, ::GetModuleHandleW(nullptr), nullptr);
            ~owner() {
                if (h != nullptr) {
                    ::DestroyWindow(h);
                }
            }
        };

        struct clipguard {
            ~clipguard() {
                ::CloseClipboard();
            }
        };

        bool open_clip(HWND w) {
            for (int i = 0; i < 20; ++i) {
                if (::OpenClipboard(w)) {
                    return true;
                }
                ::Sleep(25);
            }
            return false;
        }

        HGLOBAL make_text(std::span<const std::byte> text) {
            const char* src = reinterpret_cast<const char*>(text.data());
            const int len = static_cast<int>(text.size());
            int n = 0;
            if (len > 0) {
                n = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, len, nullptr, 0);
                if (n <= 0) {
                    throw std::runtime_error("text is not valid UTF-8");
                }
            }

            HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, (static_cast<SIZE_T>(n) + 1) * sizeof(wchar_t));
            if (h == nullptr) {
                throw std::runtime_error("out of memory");
            }
            auto* w = static_cast<wchar_t*>(::GlobalLock(h));
            if (w == nullptr) {
                ::GlobalFree(h);
                throw std::runtime_error("out of memory");
            }
            if (n > 0) {
                ::MultiByteToWideChar(CP_UTF8, 0, src, len, w, n);
            }
            w[n] = L'\0';
            ::GlobalUnlock(h);
            return h;
        }

        void set_flag(const wchar_t* name, DWORD value) {
            const UINT fmt = ::RegisterClipboardFormatW(name);
            if (fmt == 0) {
                return;
            }
            HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
            if (h == nullptr) {
                return;
            }
            auto* p = static_cast<DWORD*>(::GlobalLock(h));
            if (p == nullptr) {
                ::GlobalFree(h);
                return;
            }
            *p = value;
            ::GlobalUnlock(h);
            if (::SetClipboardData(fmt, h) == nullptr) {
                ::GlobalFree(h);
            }
        }

    }

    void cliphold(std::span<const std::byte> text, unsigned seconds) {
        const stopper stop;
        const owner win;
        if (win.h == nullptr) {
            throw std::runtime_error("cannot create the clipboard owner window");
        }

        HGLOBAL h = make_text(text);
        {
            if (!open_clip(win.h)) {
                ::GlobalFree(h);
                throw std::runtime_error("the clipboard is busy");
            }
            const clipguard guard;
            ::EmptyClipboard();
            if (::SetClipboardData(CF_UNICODETEXT, h) == nullptr) {
                ::GlobalFree(h);
                throw std::runtime_error("cannot set the clipboard");
            }
            // best effort: older Windows versions ignore these
            set_flag(L"ExcludeClipboardContentFromMonitorProcessing", 1);
            set_flag(L"CanIncludeInClipboardHistory", 0);
            set_flag(L"CanUploadToCloudClipboard", 0);
        }
        const DWORD seq = ::GetClipboardSequenceNumber();

        const auto ms = static_cast<DWORD>(std::min<unsigned long long>(seconds * 1000ull, 0xFFFFFFFEull));
        ::WaitForSingleObject(g_stop, ms);

        // only clear what we put there, never something copied in the meantime
        if (::GetClipboardSequenceNumber() == seq && open_clip(win.h)) {
            ::EmptyClipboard();
            ::CloseClipboard();
        }
    }

#else

    void cliphold(std::span<const std::byte>, unsigned) {
        throw std::runtime_error("the clipboard is not supported on this platform yet");
    }

#endif

}
