#include "credgen.h"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace kwr {
    namespace {

        constexpr std::string_view LOWER = "abcdefghijklmnopqrstuvwxyz";
        constexpr std::string_view UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        constexpr std::string_view DIGITS = "0123456789";
        constexpr std::string_view AMBIGUOUS = "0O1lI|";

        struct charset {
            std::vector<std::string> classes;
            std::string all;
        };

        std::string strip(std::string_view src, bool no_ambiguous) {
            std::string out;
            for (char c : src) {
                if (!no_ambiguous || AMBIGUOUS.find(c) == std::string_view::npos) {
                    out.push_back(c);
                }
            }
            return out;
        }

        charset build(const pwpol& p) {
            std::string symbols = p.symbols;
            for (char c : symbols) {
                const auto u = static_cast<unsigned char>(c);
                if (u < 0x21 || u > 0x7E || std::isalnum(u)) {
                    throw std::invalid_argument("pwpol: symbols must be printable non-alphanumeric ASCII");
                }
            }
            std::sort(symbols.begin(), symbols.end());
            symbols.erase(std::unique(symbols.begin(), symbols.end()), symbols.end());

            charset cs;
            const auto add = [&](bool on, std::string_view src) {
                std::string s = strip(src, p.no_ambiguous);
                if (on && !s.empty()) {
                    cs.all += s;
                    cs.classes.push_back(std::move(s));
                }
                };
            add(p.lower, LOWER);
            add(p.upper, UPPER);
            add(p.digits, DIGITS);
            add(true, symbols);

            if (cs.all.size() < 2) {
                throw std::invalid_argument("pwpol: alphabet too small");
            }
            return cs;
        }

        std::size_t length_for(const charset& cs, std::size_t want) {
            if (want < PW_MINLEN || want > PW_MAXLEN) {
                throw std::invalid_argument("pw: length out of range");
            }
            const double bits = std::log2(static_cast<double>(cs.all.size()));
            auto len = std::max(static_cast<std::size_t>(std::ceil(PW_MINBITS / bits)), want);
            // guard against floating point rounding at the boundary
            while (static_cast<double>(len) * bits < PW_MINBITS) {
                ++len;
            }
            if (len > PW_MAXLEN) {
                throw std::invalid_argument("pw: policy needs more than the maximum length");
            }
            return len;
        }

        bool has_all(const secret_buffer& buf, const std::vector<std::string>& classes) {
            const auto bytes = buf.bytes();
            for (const auto& cls : classes) {
                const bool hit = std::any_of(bytes.begin(), bytes.end(), [&](std::byte b) {
                    return cls.find(static_cast<char>(b)) != std::string::npos;
                    });
                if (!hit) {
                    return false;
                }
            }
            return true;
        }

        void init() {
            static const bool ok = sodium_init() >= 0;
            if (!ok) {
                throw std::runtime_error("sodium_init failed");
            }
        }

    }

    std::size_t pwalpha(const pwpol& p) {
        return build(p).all.size();
    }

    std::size_t pwlen(const pwpol& p, std::size_t want) {
        return length_for(build(p), want);
    }

    secret_buffer pwgen(const pwpol& p, std::size_t want) {
        const charset cs = build(p);
        const std::size_t len = length_for(cs, want);
        init();

        secret_buffer out(len);
        out.resize(len);
        const auto n = static_cast<std::uint32_t>(cs.all.size());

        // redraw the whole string until every class is present; this keeps the
        // result uniform over the constrained set, unlike patching in characters
        do {
            for (std::byte& b : out.bytes()) {
                b = static_cast<std::byte>(cs.all[randombytes_uniform(n)]);
            }
        } while (!has_all(out, cs.classes));

        return out;
    }

}
