#include <keywright/secrets.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

using kwr::secret_buffer;

namespace {

    bool all_equal(const std::byte* p, std::size_t n, std::byte v) {
        return std::all_of(p, p + n, [v](std::byte b) { return b == v; });
    }

    void fill(secret_buffer& b, std::byte v) {
        std::fill_n(b.data(), b.size(), v);
    }

}

TEST_CASE("swipe zeroes memory") {
    std::array<unsigned char, 32> a;
    a.fill(0xAB);
    kwr::swipe(a.data(), a.size());
    CHECK(std::all_of(a.begin(), a.end(), [](unsigned char c) { return c == 0; }));
}

TEST_CASE("swipe accepts null and zero size") {
    kwr::swipe(nullptr, 16);
    unsigned char c = 0x7F;
    kwr::swipe(&c, 0);
    CHECK(c == 0x7F);
}

TEST_CASE("secret_buffer starts empty") {
    secret_buffer b(64);
    CHECK(b.size() == 0);
    CHECK(b.capacity() == 64);
    CHECK(b.bytes().empty());
}

TEST_CASE("zero capacity buffer") {
    secret_buffer b(0);
    CHECK(b.data() == nullptr);
    CHECK_NOTHROW(b.resize(0));
    CHECK_THROWS_AS(b.resize(1), std::length_error);
    CHECK_NOTHROW(b.clear());
}

TEST_CASE("resize is bounded by capacity") {
    secret_buffer b(16);
    CHECK_NOTHROW(b.resize(16));
    CHECK(b.size() == 16);
    CHECK_THROWS_AS(b.resize(17), std::length_error);
    CHECK(b.size() == 16);
}

TEST_CASE("shrinking wipes and growing exposes zeros") {
    secret_buffer b(32);
    b.resize(32);
    fill(b, std::byte{ 0xAA });
    b.resize(8);
    b.resize(32);
    CHECK(all_equal(b.data(), 8, std::byte{ 0xAA }));
    CHECK(all_equal(b.data() + 8, 24, std::byte{ 0 }));
}

TEST_CASE("clear wipes the whole buffer") {
    secret_buffer b(32);
    b.resize(32);
    fill(b, std::byte{ 0xAA });
    b.clear();
    CHECK(b.size() == 0);
    b.resize(32);
    CHECK(all_equal(b.data(), 32, std::byte{ 0 }));
}

TEST_CASE("move construction transfers ownership") {
    secret_buffer a(16);
    a.resize(4);
    const std::byte* p = a.data();

    secret_buffer b(std::move(a));

    CHECK(b.data() == p);
    CHECK(b.size() == 4);
    CHECK(b.capacity() == 16);
    CHECK(a.data() == nullptr);
    CHECK(a.size() == 0);
    CHECK(a.capacity() == 0);
    CHECK_FALSE(a.locked());
}

TEST_CASE("move assignment releases the old buffer and transfers ownership") {
    secret_buffer a(16);
    a.resize(4);
    const std::byte* p = a.data();
    secret_buffer b(8);

    b = std::move(a);

    CHECK(b.data() == p);
    CHECK(b.size() == 4);
    CHECK(b.capacity() == 16);
    CHECK(a.data() == nullptr);
    CHECK(a.capacity() == 0);
}
