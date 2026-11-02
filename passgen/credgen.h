#pragma once

#include <keywright/secrets.h>

#include <cstddef>
#include <string>

namespace kwr {

    inline constexpr std::size_t PW_MINLEN = 16;
    inline constexpr std::size_t PW_MAXLEN = 256;
    inline constexpr double PW_MINBITS = 100.0;

    struct pwpol {
        bool lower = true;
        bool upper = true;
        bool digits = true;
        bool no_ambiguous = false;
        std::string symbols = "!@#$%^&*()-_=+[]{};:,.?";
    };

    std::size_t pwalpha(const pwpol& p);
    std::size_t pwlen(const pwpol& p, std::size_t want);
    secret_buffer pwgen(const pwpol& p, std::size_t want);

}
