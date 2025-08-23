#pragma once
#include <execution>

#include "../include/randutils.hpp"
#include "../include/pcg/pcg_random.hpp"

namespace randutils {    
    using pcg_rng = random_generator<pcg32>;
}

namespace utils {
    namespace random {
        inline randutils::pcg_rng get_generator_static()
        {
            static randutils::pcg_rng pcg_rng{};
            return pcg_rng;
        }

        inline randutils::pcg_rng get_generator_thread_local()
        {
            thread_local randutils::pcg_rng pcg_rng{};
            return pcg_rng;
        }

        inline randutils::pcg_rng get_generator_local()
        {
            randutils::pcg_rng pcg_rng{};
            return pcg_rng;
        }

        template <class T>
        inline std::string generate(T gen, std::size_t length,
            const std::string &chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        {
            std::string result;
            result.reserve(length);

            std::generate_n(std::back_inserter(result), length, [&]() {
                return chars[gen.uniform(static_cast<std::size_t>(0), chars.length() - 1)];
            });

            return result;
        }

        template <typename T>
        inline std::string generate_alpha(T gen, std::size_t length, bool uppercase = false)
        {
            return generate(gen, length, uppercase
                ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                : "abcdefghijklmnopqrstuvwxyz");
        }

        template <typename T>
        inline std::string generate_number(T gen, std::size_t length)
        {
            return generate(gen, length, "0123456789");
        }

        template <typename T>
        inline std::string generate_hex(T gen, std::size_t length, bool uppercase = true)
        {
            return generate(gen, length * 2, uppercase
                ? "0123456789ABCDEF"
                : "0123456789abcdef");
        }

        template <class T>
        inline std::string generate_mac(T gen)
        {
            std::string result;
            result.reserve(17);

            for (std::size_t i = 0; i < 6; i++) {
                result.append(generate_hex(gen, 1, false));
                result.push_back(':');
            }

            result.pop_back();
            return result;
        }
    }
}