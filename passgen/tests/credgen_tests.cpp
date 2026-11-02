#include "credgen.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace kwr;

namespace {

    std::string str(const secret_buffer& b) {
        const auto s = b.bytes();
        return { reinterpret_cast<const char*>(s.data()), s.size() };
    }

    bool has_any(const std::string& s, std::string_view set) {
        return s.find_first_of(set) != std::string::npos;
    }

    pwpol digits_only() {
        pwpol p;
        p.lower = false;
        p.upper = false;
        p.symbols.clear();
        return p;
    }

}

TEST_CASE("pwalpha counts distinct characters") {
    pwpol p;
    CHECK(pwalpha(p) == 62 + p.symbols.size());

    p.no_ambiguous = true;
    CHECK(pwalpha(p) == 57 + p.symbols.size());

    pwpol q = digits_only();
    q.digits = false;
    q.symbols = "!!!??";
    CHECK(pwalpha(q) == 2);
}

TEST_CASE("pwalpha rejects unusable policies") {
    pwpol none = digits_only();
    none.digits = false;
    CHECK_THROWS_AS(pwalpha(none), std::invalid_argument);

    pwpol one = none;
    one.symbols = "!";
    CHECK_THROWS_AS(pwalpha(one), std::invalid_argument);

    pwpol bad;
    bad.symbols = "a";
    CHECK_THROWS_AS(pwalpha(bad), std::invalid_argument);
    bad.symbols = " ";
    CHECK_THROWS_AS(pwalpha(bad), std::invalid_argument);
}

TEST_CASE("pwlen reaches the entropy floor") {
    CHECK(pwlen(pwpol{}, 16) == 16);
    CHECK(pwlen(pwpol{}, 40) == 40);
    CHECK(pwlen(digits_only(), 16) == 31);
    CHECK(pwlen(digits_only(), 50) == 50);

    pwpol two = digits_only();
    two.digits = false;
    two.symbols = "!?";
    CHECK(pwlen(two, 16) == 100);
}

TEST_CASE("pwlen enforces the length range") {
    CHECK_THROWS_AS(pwlen(pwpol{}, PW_MINLEN - 1), std::invalid_argument);
    CHECK_THROWS_AS(pwlen(pwpol{}, PW_MAXLEN + 1), std::invalid_argument);
    CHECK_NOTHROW(pwlen(pwpol{}, PW_MAXLEN));
}

TEST_CASE("pwgen returns the computed length") {
    const pwpol p;
    for (std::size_t want : {16u, 24u, 100u, 256u}) {
        const auto pw = pwgen(p, want);
        CHECK(pw.size() == pwlen(p, want));
    }
}

TEST_CASE("pwgen includes every enabled class") {
    const pwpol p;
    for (int i = 0; i < 200; ++i) {
        const auto s = str(pwgen(p, PW_MINLEN));
        CHECK(has_any(s, "abcdefghijklmnopqrstuvwxyz"));
        CHECK(has_any(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        CHECK(has_any(s, "0123456789"));
        CHECK(has_any(s, p.symbols));
    }
}

TEST_CASE("pwgen keeps a rare class present") {
    pwpol p = digits_only();
    p.symbols = "!";
    for (int i = 0; i < 200; ++i) {
        const auto s = str(pwgen(p, PW_MINLEN));
        CHECK(has_any(s, "!"));
        CHECK(has_any(s, "0123456789"));
    }
}

TEST_CASE("pwgen respects disabled classes and ambiguity") {
    pwpol p;
    p.digits = false;
    p.symbols.clear();
    p.no_ambiguous = true;
    for (int i = 0; i < 200; ++i) {
        const auto s = str(pwgen(p, PW_MINLEN));
        CHECK_FALSE(has_any(s, "0123456789"));
        CHECK_FALSE(has_any(s, "O1lI|"));
        CHECK(s.find_first_not_of("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ") == std::string::npos);
    }
}

TEST_CASE("pwgen output differs between calls") {
    const pwpol p;
    CHECK(str(pwgen(p, 24)) != str(pwgen(p, 24)));
}

TEST_CASE("pwgen is uniform over the alphabet") {
    const pwpol p = digits_only();
    std::array<double, 10> count{};
    double total = 0;

    for (int i = 0; i < 20000; ++i) {
        for (char c : str(pwgen(p, PW_MINLEN))) {
            ++count[c - '0'];
            ++total;
        }
    }

    const double expect = total / 10;
    double chi = 0;
    for (double c : count) {
        chi += (c - expect) * (c - expect) / expect;
    }
    // df = 9, so this threshold fails by chance about once in 100,000 runs
    CHECK(chi < 40.0);
}
