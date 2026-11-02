#pragma once

#include <cstddef>
#include <span>

namespace kwr {

    /// <summary>
    /// Zeroes memory in a way the compiler cannot optimize away. Accepts null and zero size.
    /// </summary>
    void swipe(void* p, std::size_t size) noexcept;

    /// <summary>
    /// Fixed-capacity, non-copyable buffer for secrets. Memory is page-locked on a best-effort
    /// basis and wiped on destruction, `clear()`.
    /// A moved-from buffer is left empty.
    /// </summary>
    class secret_buffer {
    public:
        /// <exception cref="std::bad_alloc">Allocation failed. A failed page lock does not throw.</exception>
        explicit secret_buffer(std::size_t capacity);
        ~secret_buffer();

        secret_buffer(const secret_buffer&) = delete;
        secret_buffer& operator=(const secret_buffer&) = delete;
        secret_buffer(secret_buffer&& other) noexcept;
        secret_buffer& operator=(secret_buffer&& other) noexcept;

        std::byte* data() noexcept;
        const std::byte* data() const noexcept;
        std::span<std::byte> bytes() noexcept;
        std::span<const std::byte> bytes() const noexcept;

        std::size_t size() const noexcept;
        std::size_t capacity() const noexcept;

        /// <summary>True if the pages are locked in RAM (not swappable).</summary>
        bool locked() const noexcept;

        /// <summary>Sets the logical size. Bytes exposed by growing are zero.</summary>
        /// <exception cref="std::length_error">n exceeds capacity.</exception>
        void resize(std::size_t n);

        /// <summary>Wipes the whole buffer and sets size to 0.</summary>
        void clear() noexcept;

    private:
        std::byte* data_ = nullptr;
        std::size_t size_ = 0;
        std::size_t capacity_ = 0;
        bool locked_ = false;
    };
}
