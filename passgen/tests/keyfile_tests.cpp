#include "../keyfile.h"

#include <keywright/platform.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <random>
#include <string>

using namespace kwr;
namespace fs = std::filesystem;

namespace {

    struct tmpdir {
        fs::path p;
        tmpdir() {
            p = fs::temp_directory_path() / ("kwr-keyfile-" + std::to_string(std::random_device{}()));
            fs::create_directories(p);
        }
        ~tmpdir() {
            std::error_code ec;
            fs::remove_all(p, ec);
        }
        std::string file(const char* name) const { return (p / name).string(); }
    };

}

TEST_CASE("keymake writes exactly KEY_BYTES bytes", "[keyfile]") {
    tmpdir d;
    const std::string f = d.file("a.key");
    keymake(f);
    CHECK(readfile(f).size() == KEY_BYTES);
}

TEST_CASE("keymake output is not constant", "[keyfile]") {
    tmpdir d;
    keymake(d.file("a.key"));
    const auto b = readfile(d.file("a.key"));
    CHECK(std::any_of(b.begin(), b.end(), [&](auto x) { return x != b.front(); }));
}

TEST_CASE("two keyfiles differ", "[keyfile]") {
    tmpdir d;
    keymake(d.file("a.key"));
    keymake(d.file("b.key"));
    CHECK(readfile(d.file("a.key")) != readfile(d.file("b.key")));
}

TEST_CASE("keymake refuses to overwrite and leaves the file intact", "[keyfile]") {
    tmpdir d;
    const std::string f = d.file("a.key");
    keymake(f);
    const auto before = readfile(f);
    CHECK_THROWS(keymake(f));
    CHECK(readfile(f) == before);
}

TEST_CASE("keymake fails when the directory does not exist", "[keyfile]") {
    tmpdir d;
    CHECK_THROWS(keymake((d.p / "missing" / "a.key").string()));
}
