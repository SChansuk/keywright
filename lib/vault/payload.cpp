#include "internal.h"

#include <sodium.h>

#include <algorithm>
#include <optional>
#include <set>
#include <stdexcept>
#include <vector>

namespace kwr {
    namespace {

        constexpr std::uint8_t T_NS = 1;
        constexpr std::uint8_t T_ACCT = 10;
        constexpr std::uint8_t T_USER = 1;
        constexpr std::uint8_t T_PW = 2;
        constexpr std::uint8_t T_MADE = 3;
        constexpr std::uint8_t T_OLD = 4;
        constexpr std::uint8_t T_RETIRED = 5;
        constexpr std::size_t MAXPW = 256;

        constexpr std::size_t tlv(std::size_t n) {
            return 3 + n;
        }

        std::size_t inner(const std::string& user, const vacct& a) {
            std::size_t n = tlv(user.size()) + tlv(a.pw.size()) + tlv(8);
            if (a.old) {
                n += tlv(a.old->size()) + tlv(8);
            }
            return n;
        }

        struct wr {
            std::byte* p;
            std::size_t pos = 0;

            void u8(std::uint8_t v) {
                p[pos++] = static_cast<std::byte>(v);
            }
            void head(std::uint8_t tag, std::size_t len) {
                u8(tag);
                u8(static_cast<std::uint8_t>(len & 0xFF));
                u8(static_cast<std::uint8_t>((len >> 8) & 0xFF));
            }
            void bytes(std::uint8_t tag, std::span<const std::byte> v) {
                head(tag, v.size());
                std::copy(v.begin(), v.end(), p + pos);
                pos += v.size();
            }
            void i64(std::uint8_t tag, std::int64_t v) {
                head(tag, 8);
                auto x = static_cast<std::uint64_t>(v);
                for (int i = 0; i < 8; ++i) {
                    u8(static_cast<std::uint8_t>(x & 0xFF));
                    x >>= 8;
                }
            }
        };

        struct rd {
            std::span<const std::byte> s;

            bool next(std::uint8_t& tag, std::span<const std::byte>& v) {
                if (s.empty()) {
                    return false;
                }
                if (s.size() < 3) {
                    vfail();
                }
                tag = std::to_integer<std::uint8_t>(s[0]);
                const std::size_t len =
                    std::to_integer<std::size_t>(s[1]) | (std::to_integer<std::size_t>(s[2]) << 8);
                if (s.size() - 3 < len) {
                    vfail();
                }
                v = s.subspan(3, len);
                s = s.subspan(3 + len);
                return true;
            }
        };

        secret_buffer secret(std::span<const std::byte> v) {
            secret_buffer b(v.size());
            b.resize(v.size());
            std::copy(v.begin(), v.end(), b.data());
            return b;
        }

        std::int64_t rd64(std::span<const std::byte> v) {
            if (v.size() != 8) {
                vfail();
            }
            std::uint64_t x = 0;
            for (int i = 7; i >= 0; --i) {
                x = (x << 8) | std::to_integer<std::uint64_t>(v[static_cast<std::size_t>(i)]);
            }
            return static_cast<std::int64_t>(x);
        }

        vacct unpack_acct(std::span<const std::byte> in) {
            rd r{ in };
            std::uint8_t tag = 0;
            std::span<const std::byte> v;
            std::string user;
            std::optional<secret_buffer> pw;
            std::optional<secret_buffer> old;
            std::int64_t made = 0;
            std::int64_t retired = 0;

            while (r.next(tag, v)) {
                switch (tag) {
                case T_USER:
                    user.assign(reinterpret_cast<const char*>(v.data()), v.size());
                    break;
                case T_PW:
                    pw = secret(v);
                    break;
                case T_MADE:
                    made = rd64(v);
                    break;
                case T_OLD:
                    old = secret(v);
                    break;
                case T_RETIRED:
                    retired = rd64(v);
                    break;
                default:
                    break;
                }
            }

            if (user.empty() || !pw || pw->size() == 0) {
                vfail();
            }
            return vacct{ std::move(user), std::move(*pw), made, std::move(old), retired };
        }

    }

    secret_buffer vpack(const vdata& d, std::uint8_t& b) {
        const std::string ns = vnorm(d.ns);

        std::vector<std::string> users;
        std::set<std::string> seen;
        std::size_t total = 4 + tlv(ns.size());
        for (const vacct& a : d.accts) {
            std::string u = vnorm(a.user);
            if (!seen.insert(u).second) {
                throw std::invalid_argument("duplicate username");
            }
            if (a.pw.size() == 0 || a.pw.size() > MAXPW ||
                (a.old && (a.old->size() == 0 || a.old->size() > MAXPW))) {
                throw std::invalid_argument("password must be 1 to 256 bytes");
            }
            total += tlv(inner(u, a));
            users.push_back(std::move(u));
        }

        b = 0;
        while (b <= V_MAXB && total > vsize(b)) {
            ++b;
        }
        if (b > V_MAXB) {
            throw std::invalid_argument("too many accounts");
        }

        vready();
        const std::size_t size = vsize(b);
        secret_buffer pt(size);
        pt.resize(size);

        wr w{ pt.data() };
        w.pos = 4;
        w.bytes(T_NS, vbytes(ns));
        for (std::size_t i = 0; i < d.accts.size(); ++i) {
            const vacct& a = d.accts[i];
            w.head(T_ACCT, inner(users[i], a));
            w.bytes(T_USER, vbytes(users[i]));
            w.bytes(T_PW, a.pw.bytes());
            w.i64(T_MADE, a.made);
            if (a.old) {
                w.bytes(T_OLD, a.old->bytes());
                w.i64(T_RETIRED, a.retired);
            }
        }

        const std::size_t len = w.pos - 4;
        for (std::size_t i = 0; i < 4; ++i) {
            pt.data()[i] = static_cast<std::byte>((len >> (8 * i)) & 0xFF);
        }
        randombytes_buf(pt.data() + w.pos, size - w.pos);
        return pt;
    }

    vdata vunpack(std::span<const std::byte> pt) {
        if (pt.size() < 4) {
            vfail();
        }
        std::size_t len = 0;
        for (std::size_t i = 4; i-- > 0;) {
            len = (len << 8) | std::to_integer<std::size_t>(pt[i]);
        }
        if (len > pt.size() - 4) {
            vfail();
        }

        vdata d;
        rd top{ pt.subspan(4, len) };
        std::uint8_t tag = 0;
        std::span<const std::byte> v;
        std::set<std::string> seen;

        while (top.next(tag, v)) {
            if (tag == T_NS) {
                if (!d.ns.empty()) {
                    vfail();
                }
                d.ns.assign(reinterpret_cast<const char*>(v.data()), v.size());
            }
            else if (tag == T_ACCT) {
                d.accts.push_back(unpack_acct(v));
                if (!seen.insert(d.accts.back().user).second) {
                    vfail();
                }
            }
        }
        if (d.ns.empty()) {
            vfail();
        }
        return d;
    }

}
