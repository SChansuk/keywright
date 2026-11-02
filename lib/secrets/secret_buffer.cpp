#include <keywright/secrets.h>

#include <new>
#include <stdexcept>
#include <utility>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace kwr {
    namespace {

        std::byte* allocate(std::size_t size, bool& locked) {
#if defined(_WIN32)
            void* p = ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (p == nullptr) {
                throw std::bad_alloc();
            }
            locked = ::VirtualLock(p, size) != 0;
#else
            void* p = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) {
                throw std::bad_alloc();
            }
#if defined(MADV_DONTDUMP)
            ::madvise(p, size, MADV_DONTDUMP);
#endif
            locked = ::mlock(p, size) == 0;
#endif
            return static_cast<std::byte*>(p);
        }

        void destroy(std::byte* p, std::size_t size, bool locked) noexcept {
            if (p == nullptr) {
                return;
            }
            swipe(p, size);
#if defined(_WIN32)
            if (locked) {
                ::VirtualUnlock(p, size);
            }
            ::VirtualFree(p, 0, MEM_RELEASE);
#else
            if (locked) {
                ::munlock(p, size);
            }
            ::munmap(p, size);
#endif
        }

    }

    secret_buffer::secret_buffer(std::size_t capacity) : capacity_(capacity) {
        if (capacity_ > 0) {
            data_ = allocate(capacity_, locked_);
        }
    }

    secret_buffer::~secret_buffer() {
        destroy(data_, capacity_, locked_);
    }

    secret_buffer::secret_buffer(secret_buffer&& other) noexcept
        : data_(std::exchange(other.data_, nullptr)),
        size_(std::exchange(other.size_, 0)),
        capacity_(std::exchange(other.capacity_, 0)),
        locked_(std::exchange(other.locked_, false)) {
    }

    secret_buffer& secret_buffer::operator=(secret_buffer&& other) noexcept {
        if (this != &other) {
            destroy(data_, capacity_, locked_);
            data_ = std::exchange(other.data_, nullptr);
            size_ = std::exchange(other.size_, 0);
            capacity_ = std::exchange(other.capacity_, 0);
            locked_ = std::exchange(other.locked_, false);
        }
        return *this;
    }

    std::byte* secret_buffer::data() noexcept { return data_; }
    const std::byte* secret_buffer::data() const noexcept { return data_; }

    std::span<std::byte> secret_buffer::bytes() noexcept { return { data_, size_ }; }
    std::span<const std::byte> secret_buffer::bytes() const noexcept { return { data_, size_ }; }

    std::size_t secret_buffer::size() const noexcept { return size_; }
    std::size_t secret_buffer::capacity() const noexcept { return capacity_; }
    bool secret_buffer::locked() const noexcept { return locked_; }

    void secret_buffer::resize(std::size_t n) {
        if (n > capacity_) {
            throw std::length_error("secret_buffer: size exceeds capacity");
        }
        // everything past size_ is kept zero, so growing never exposes stale bytes
        if (n < size_) {
            swipe(data_ + n, size_ - n);
        }
        size_ = n;
    }

    void secret_buffer::clear() noexcept {
        swipe(data_, capacity_);
        size_ = 0;
    }

}
