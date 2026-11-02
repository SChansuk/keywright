#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#if !defined(__APPLE__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>
#endif

#include <keywright/secrets.h>

namespace kwr {

    void swipe(void* p, std::size_t size) noexcept {
        if (p == nullptr || size == 0) {
            return;
        }

#if defined(_WIN32)
        ::SecureZeroMemory(p, size);
#elif defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
        ::memset_s(p, size, 0, size);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__GLIBC__)
        ::explicit_bzero(p, size);
#else
        auto* v = static_cast<volatile unsigned char*>(p);
        while (size--) {
            *v++ = 0;
        }
#endif
    }

}
