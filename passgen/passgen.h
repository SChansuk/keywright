#pragma once

#include <cstddef>
#include <string>

namespace kwr {

    struct options {
        std::string ns;
        std::string user;
        std::size_t min_len = 0;
        std::string save_to;
        std::string keyfile;
        std::string make_keyfile;
        unsigned clip_timeout = 0;
        bool get = false;
        bool list = false;
        bool no_save = false;
        bool force = false;
        bool previous = false;
        bool print = false;
    };

}
