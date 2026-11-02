#include <keywright/vault.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace kwr;

namespace {

    std::vector<std::byte> to_bytes(std::string_view s) {
        const auto* p = reinterpret_cast<const std::byte*>(s.data());
        return { p, p + s.size() };
    }

    std::vector<std::byte> make_keyfile(unsigned seed, std::size_t n = 64) {
        std::vector<std::byte> k(n);
        for (std::size_t i = 0; i < n; ++i) {
            k[i] = static_cast<std::byte>((seed + i * 7) & 0xFF);
        }
        return k;
    }

    const std::vector<std::byte> PASS = to_bytes("correct horse battery staple");
    const std::vector<std::byte> KEY = make_keyfile(0x11);
    const std::vector<std::byte> OTHER_KEY = make_keyfile(0x42);

    secret_buffer sec(std::string_view s) {
        secret_buffer b(s.size());
        b.resize(s.size());
        std::copy(s.begin(), s.end(), reinterpret_cast<char*>(b.data()));
        return b;
    }

    std::string str(const secret_buffer& b) {
        return { reinterpret_cast<const char*>(b.data()), b.size() };
    }

    vacct acct(std::string user, std::string_view pw, std::int64_t made) {
        return vacct{ std::move(user), sec(pw), made, std::nullopt, 0 };
    }

    vdata sample() {
        vdata d;
        d.ns = "x-twitter";
        d.accts.push_back(acct("account1", "pw-one-0123456789abcdef", 1000));
        d.accts.push_back(acct("account2", "pw-two-0123456789abcdef", 2000));
        return d;
    }

    // one seal shared by every test that only needs a valid blob, since each KDF run costs about a second
    const std::vector<std::byte>& sealed() {
        static const std::vector<std::byte> blob = vseal(sample(), PASS, KEY, vkdf::moderate);
        return blob;
    }

    vdata open(const std::vector<std::byte>& blob, std::string_view ns = "x-twitter") {
        return vopen(blob, PASS, KEY, ns);
    }

    std::vector<std::byte> flip(std::vector<std::byte> blob, std::size_t off, unsigned char mask = 0x01) {
        blob[off] ^= static_cast<std::byte>(mask);
        return blob;
    }

    template <class F>
    std::string error_of(F&& f) {
        try {
            f();
        }
        catch (const std::exception& e) {
            return e.what();
        }
        return {};
    }

}

TEST_CASE("vfname is deterministic, keyed, and well formed") {
    const std::string n = vfname(KEY, "x-twitter");
    CHECK(n.size() == 26);
    CHECK(n.find_first_not_of("abcdefghijklmnopqrstuvwxyz234567") == std::string::npos);
    CHECK(n == vfname(KEY, "x-twitter"));
    CHECK(n != vfname(KEY, "x-mastodon"));
    CHECK(n != vfname(OTHER_KEY, "x-twitter"));
    CHECK(vfname(KEY, "Namespace") != vfname(KEY, "namespace"));
}

TEST_CASE("vfname normalizes Unicode") {
    CHECK(vfname(KEY, "caf\xC3\xA9") == vfname(KEY, "cafe\xCC\x81"));
}

TEST_CASE("vfname rejects bad input") {
    CHECK_THROWS_AS(vfname(make_keyfile(1, 16), "ns"), std::invalid_argument);
    CHECK_THROWS_AS(vfname(KEY, ""), std::invalid_argument);
    CHECK_THROWS_AS(vfname(KEY, "a\tb"), std::invalid_argument);
    CHECK_THROWS_AS(vfname(KEY, std::string(65, 'a')), std::invalid_argument);
    CHECK_THROWS_AS(vfname(KEY, "\xFF\xFE"), std::invalid_argument);
    CHECK_NOTHROW(vfname(KEY, std::string(64, 'a')));
}

TEST_CASE("round trip preserves every field") {
    const vdata d = open(sealed());
    REQUIRE(d.ns == "x-twitter");
    REQUIRE(d.accts.size() == 2);
    CHECK(d.accts[0].user == "account1");
    CHECK(str(d.accts[0].pw) == "pw-one-0123456789abcdef");
    CHECK(d.accts[0].made == 1000);
    CHECK_FALSE(d.accts[0].old.has_value());
    CHECK(d.accts[1].user == "account2");
    CHECK(str(d.accts[1].pw) == "pw-two-0123456789abcdef");
    CHECK(d.accts[1].made == 2000);
}

TEST_CASE("file has the fixed first-bucket size and no plaintext") {
    const auto& blob = sealed();
    CHECK(blob.size() == 48 + 1024);

    for (std::string_view needle : {"account1", "pw-one", "x-twitter"}) {
        const auto n = to_bytes(needle);
        CHECK(std::search(blob.begin(), blob.end(), n.begin(), n.end()) == blob.end());
    }
}

TEST_CASE("two seals of the same data differ") {
    const auto again = vseal(sample(), PASS, KEY, vkdf::moderate);
    REQUIRE(again.size() == sealed().size());
    CHECK(again != sealed());
    CHECK(std::equal(again.begin(), again.begin() + 16, sealed().begin()) == false);
    CHECK(std::equal(again.begin() + 16, again.begin() + 40, sealed().begin() + 16) == false);
}

TEST_CASE("every open failure is the same error") {
    const std::string msg = "cannot open vault";
    CHECK(error_of([] { (void)vopen(sealed(), to_bytes("wrong passphrase"), KEY, "x-twitter"); }) == msg);
    CHECK(error_of([] { (void)vopen(sealed(), PASS, OTHER_KEY, "x-twitter"); }) == msg);
    CHECK(error_of([] { (void)vopen(sealed(), PASS, KEY, "other-ns"); }) == msg);
}

TEST_CASE("tampering anywhere fails authentication") {
    const auto& blob = sealed();
    const std::size_t last = blob.size() - 1;
    // header offsets 40-47 are masked, so these flip real header fields too
    for (std::size_t off : {std::size_t{ 0 }, std::size_t{ 15 }, std::size_t{ 16 }, std::size_t{ 39 },
        std::size_t{ 41 }, std::size_t{ 44 }, std::size_t{ 47 }, std::size_t{ 48 },
        std::size_t{ 600 }, last - 16, last}) {
        CAPTURE(off);
        CHECK_THROWS_AS(open(flip(blob, off)), vault_error);
    }
}

TEST_CASE("hostile header parameters are rejected") {
    const auto& blob = sealed();
    CHECK_THROWS_AS(open(flip(blob, 40)), vault_error);
    CHECK_THROWS_AS(open(flip(blob, 41, 0x80)), vault_error);
    CHECK_THROWS_AS(open(flip(blob, 42, 0x80)), vault_error);
    CHECK_THROWS_AS(open(flip(blob, 43, 0x40)), vault_error);
}

TEST_CASE("truncated, extended, and tiny files are rejected") {
    auto blob = sealed();
    CHECK_THROWS_AS(open({}), vault_error);
    CHECK_THROWS_AS(open(std::vector<std::byte>(63)), vault_error);
    CHECK_THROWS_AS(open(std::vector<std::byte>(blob.begin(), blob.end() - 1)), vault_error);
    blob.push_back(std::byte{ 0 });
    CHECK_THROWS_AS(open(blob), vault_error);
}

TEST_CASE("rotation history survives a round trip") {
    vdata d;
    d.ns = "ns";
    vacct a = acct("user", "new-password-0123456789", 5000);
    a.old = sec("old-password-0123456789");
    a.retired = 5000;
    d.accts.push_back(std::move(a));

    const auto blob = vseal(d, PASS, KEY, vkdf::moderate);
    const vdata r = vopen(blob, PASS, KEY, "ns");
    REQUIRE(r.accts.size() == 1);
    REQUIRE(r.accts[0].old.has_value());
    CHECK(str(*r.accts[0].old) == "old-password-0123456789");
    CHECK(r.accts[0].retired == 5000);
    CHECK(str(r.accts[0].pw) == "new-password-0123456789");
}

TEST_CASE("an empty namespace round trips") {
    vdata d;
    d.ns = "empty";
    const auto blob = vseal(d, PASS, KEY, vkdf::moderate);
    CHECK(blob.size() == 48 + 1024);
    CHECK(vopen(blob, PASS, KEY, "empty").accts.empty());
}

TEST_CASE("the size bucket grows with the account count") {
    vdata d;
    d.ns = "big";
    for (int i = 0; i < 30; ++i) {
        d.accts.push_back(acct("user-" + std::to_string(10 + i), "pw-0123456789abcdefghijklm", i));
    }
    const auto blob = vseal(d, PASS, KEY, vkdf::moderate);
    CHECK(blob.size() == 48 + 2048);

    const vdata r = vopen(blob, PASS, KEY, "big");
    REQUIRE(r.accts.size() == 30);
    CHECK(r.accts[29].user == "user-39");
    CHECK(r.accts[29].made == 29);
}

TEST_CASE("normalization applies to namespace and usernames") {
    vdata d;
    d.ns = "cafe\xCC\x81";
    d.accts.push_back(acct("re\xCC\x81sume\xCC\x81", "pw-0123456789abcdefghijklm", 1));
    const auto blob = vseal(d, PASS, KEY, vkdf::moderate);

    const vdata r = vopen(blob, PASS, KEY, "caf\xC3\xA9");
    CHECK(r.ns == "caf\xC3\xA9");
    REQUIRE(r.accts.size() == 1);
    CHECK(r.accts[0].user == "r\xC3\xA9sum\xC3\xA9");
}

TEST_CASE("vseal rejects invalid input without running the KDF") {
    CHECK_THROWS_AS(vseal(sample(), {}, KEY, vkdf::moderate), std::invalid_argument);
    CHECK_THROWS_AS(vseal(sample(), PASS, make_keyfile(1, 16), vkdf::moderate), std::invalid_argument);

    vdata d = sample();
    d.ns.clear();
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);

    d = sample();
    d.accts[0].user = "a\tb";
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);

    d = sample();
    d.accts[1].user = d.accts[0].user;
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);

    d = sample();
    d.accts[0].user = "\xC3\xA9";
    d.accts[1].user = "e\xCC\x81";
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);

    d = sample();
    d.accts[0].pw = secret_buffer(0);
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);

    d = sample();
    d.accts[0].pw = sec(std::string(257, 'x'));
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);
}

TEST_CASE("too many accounts for the largest bucket") {
    vdata d;
    d.ns = "huge";
    const std::string pw(256, 'x');
    for (int i = 0; i < 300; ++i) {
        d.accts.push_back(acct("u" + std::to_string(i), pw, i));
    }
    CHECK_THROWS_AS(vseal(d, PASS, KEY, vkdf::moderate), std::invalid_argument);
}

TEST_CASE("sensitive profile round trip", "[.slow]") {
    const auto blob = vseal(sample(), PASS, KEY, vkdf::sensitive);
    CHECK(blob.size() == 48 + 1024);
    CHECK(vopen(blob, PASS, KEY, "x-twitter").accts.size() == 2);
}
