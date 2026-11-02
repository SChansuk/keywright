#include <keywright/platform.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include <chrono>
#include <optional>
#include <thread>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

    std::vector<std::byte> to_bytes(std::string_view s) {
        const auto* p = reinterpret_cast<const std::byte*>(s.data());
        return { p, p + s.size() };
    }

    std::string utf8(const fs::path& p) {
        const std::u8string u = p.u8string();
        return { reinterpret_cast<const char*>(u.data()), u.size() };
    }

    struct tmpdir {
        fs::path p;

        tmpdir() {
            std::random_device rd;
            p = fs::temp_directory_path() / ("kwr-test-" + std::to_string(rd()) + std::to_string(rd()));
            fs::create_directories(p);
        }
        ~tmpdir() {
            std::error_code ec;
            fs::remove_all(p, ec);
        }
        tmpdir(const tmpdir&) = delete;
        tmpdir& operator=(const tmpdir&) = delete;

        std::string dir() const { return utf8(p); }
        std::string file(const std::string& name) const { return kwr::joinpath(dir(), name); }
        std::size_t count() const {
            return static_cast<std::size_t>(std::distance(fs::directory_iterator(p), fs::directory_iterator{}));
        }
    };

}

TEST_CASE("cfgdir is an absolute keywright folder") {
    const std::string c = kwr::cfgdir();
    REQUIRE_FALSE(c.empty());
    const fs::path p(fs::u8path(c));
    CHECK(p.is_absolute());
    CHECK(p.filename() == "keywright");
}

TEST_CASE("joinpath, isfile, and isdir") {
    tmpdir d;
    const std::string f = d.file("a.bin");

    CHECK(kwr::isdir(d.dir()));
    CHECK_FALSE(kwr::isfile(d.dir()));
    CHECK_FALSE(kwr::isfile(f));
    CHECK_FALSE(kwr::isdir(f));

    kwr::writefile(f, to_bytes("x"));
    CHECK(kwr::isfile(f));
    CHECK_FALSE(kwr::isdir(f));
    CHECK(fs::u8path(f).parent_path() == d.p);
}

TEST_CASE("writefile and readfile round trip arbitrary bytes") {
    tmpdir d;
    std::vector<std::byte> data(1500);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>(i % 7 == 0 ? 0 : i & 0xFF);
    }
    const std::string f = d.file("blob");
    kwr::writefile(f, data);
    CHECK(kwr::readfile(f) == data);
}

TEST_CASE("empty files round trip") {
    tmpdir d;
    const std::string f = d.file("empty");
    kwr::writefile(f, {});
    CHECK(kwr::readfile(f).empty());
    CHECK(kwr::readkey(f).size() == 0);
}

TEST_CASE("writefile replaces the old content and leaves no temp files") {
    tmpdir d;
    const std::string f = d.file("v.kwr");
    kwr::writefile(f, to_bytes("first version, longer than the second"));
    kwr::writefile(f, to_bytes("second"));
    CHECK(kwr::readfile(f) == to_bytes("second"));
    CHECK(d.count() == 1);
}

TEST_CASE("writefile into a missing folder fails cleanly") {
    tmpdir d;
    const std::string f = kwr::joinpath(d.file("missing"), "v.kwr");
    CHECK_THROWS_AS(kwr::writefile(f, to_bytes("x")), std::runtime_error);
    CHECK(d.count() == 0);
}

TEST_CASE("newfile refuses to overwrite") {
    tmpdir d;
    const std::string f = d.file("key");
    kwr::newfile(f, to_bytes("original"));
    CHECK_THROWS_AS(kwr::newfile(f, to_bytes("replacement")), std::runtime_error);
    CHECK(kwr::readfile(f) == to_bytes("original"));
    CHECK(d.count() == 1);
}

TEST_CASE("readfile and readkey report missing files") {
    tmpdir d;
    CHECK_THROWS_AS(kwr::readfile(d.file("nope")), std::runtime_error);
    CHECK_THROWS_AS(kwr::readkey(d.file("nope")), std::runtime_error);
}

TEST_CASE("readkey returns the bytes in a secret buffer") {
    tmpdir d;
    const std::string f = d.file("key");
    const auto data = to_bytes("0123456789abcdef0123456789abcdef");
    kwr::newfile(f, data);

    const kwr::secret_buffer k = kwr::readkey(f);
    REQUIRE(k.size() == data.size());
    CHECK(std::equal(data.begin(), data.end(), k.data()));
}

TEST_CASE("readkey enforces the 1 MiB limit") {
    tmpdir d;
    const std::size_t mib = 1024 * 1024;
    kwr::writefile(d.file("ok"), std::vector<std::byte>(mib));
    kwr::writefile(d.file("big"), std::vector<std::byte>(mib + 1));
    CHECK(kwr::readkey(d.file("ok")).size() == mib);
    CHECK_THROWS_AS(kwr::readkey(d.file("big")), std::runtime_error);
}

TEST_CASE("UTF-8 paths work") {
    tmpdir d;
    const std::string f = d.file("caf\xC3\xA9-\xE5\xAF\x86\xE9\x92\xA5.bin");
    kwr::writefile(f, to_bytes("unicode"));
    CHECK(kwr::isfile(f));
    CHECK(kwr::readfile(f) == to_bytes("unicode"));
}

TEST_CASE("mkdirs creates nested folders and is idempotent", "[platform]") {
    tmpdir d;
    const std::string deep = kwr::joinpath(kwr::joinpath(d.dir(), "a"), "b");
    kwr::mkdirs(deep);
    CHECK(kwr::isdir(deep));
    CHECK_NOTHROW(kwr::mkdirs(deep));
}

TEST_CASE("mkdirs fails when the path is a file", "[platform]") {
    tmpdir d;
    const std::string f = d.file("f");
    kwr::writefile(f, to_bytes("x"));
    CHECK_THROWS_AS(kwr::mkdirs(f), std::runtime_error);
}

TEST_CASE("abspath makes paths absolute and tidy", "[platform]") {
    tmpdir d;
    const std::string rel = kwr::abspath("some/../file.toml");
    CHECK(fs::u8path(rel).is_absolute());
    CHECK(fs::u8path(rel).filename() == "file.toml");
    CHECK(kwr::abspath(d.file("x")) == kwr::abspath(kwr::joinpath(d.dir(), "./x")));
    CHECK_THROWS_AS(kwr::abspath(""), std::runtime_error);
}

#if !defined(_WIN32)
TEST_CASE("files are created owner-only") {
    tmpdir d;
    kwr::newfile(d.file("key"), to_bytes("x"));
    kwr::writefile(d.file("vault"), to_bytes("x"));

    const auto others = fs::perms::group_all | fs::perms::others_all;
    for (const char* name : { "key", "vault" }) {
        CHECK((fs::status(fs::u8path(d.file(name))).permissions() & others) == fs::perms::none);
    }
}
#endif

#if defined(_WIN32)
namespace {

    std::optional<std::wstring> clip_text() {
        bool open = false;
        for (int i = 0; i < 20 && !open; ++i) {
            open = ::OpenClipboard(nullptr) != 0;
            if (!open) {
                ::Sleep(25);
            }
        }
        if (!open) {
            throw std::runtime_error("clipboard is busy");
        }
        std::optional<std::wstring> out;
        if (HANDLE h = ::GetClipboardData(CF_UNICODETEXT)) {
            if (const auto* w = static_cast<const wchar_t*>(::GlobalLock(h))) {
                out = std::wstring(w);
                ::GlobalUnlock(h);
            }
        }
        ::CloseClipboard();
        return out;
    }

}

// hidden by default because it overwrites whatever is on the real clipboard
TEST_CASE("cliphold sets the text and clears it afterward", "[.clipboard]") {
    std::string err;
    std::thread t([&err] {
        try {
            kwr::cliphold(to_bytes("kwr-clip-test"), 2);
        }
        catch (const std::exception& e) {
            err = e.what();
        }
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    const auto during = clip_text();
    t.join();
    const auto after = clip_text();

    CHECK(err.empty());
    REQUIRE(during.has_value());
    CHECK(*during == L"kwr-clip-test");
    CHECK_FALSE(after.has_value());
}
#endif
