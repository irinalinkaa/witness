#ifndef WITNESS_LOGGER_HPP
#define WITNESS_LOGGER_HPP

#include <websocketpp/logger/basic.hpp>

#include <stdio.h>
#include <stdlib.h>

template <typename concurrency, typename names>
class logger : public websocketpp::log::basic<concurrency, names> {
public:
    logger<concurrency, names>() { }

    using websocketpp::log::basic<concurrency, names>::basic;

    void write(uint32_t channel, const std::string& message)
    {
        if (!this->dynamic_test(channel)) {
            return;
        }

        std::string line0 = message;
        std::string line1;
        std::string line2;

        if (message.length() > 75) {
            line0 = message.substr(0,
                (line1.find(' ', 75) == std::string::npos)
                    ? 75
                    : line1.find(' ', 75));
            line1 = message.substr(
                (line1.find(' ', 75) == std::string::npos)
                    ? 75
                    : line1.find(' ', 75),
                message.length());
        }

        printf("\033[%d;%dH", m_line_level, 75);

        websocketpp::log::basic<concurrency, names>::write(
            channel, line0);

        ++m_line_level;

        if (!line1.empty()) {
            if (line1.length() > 75) {
                line1 = line1.substr(0,
                    (line1.find(' ', 75) == std::string::npos)
                        ? 75
                        : line1.find(' ', 75));
                line2 = line1.substr(
                    (line1.find(' ', 75) == std::string::npos)
                        ? 75
                        : line1.find(' ', 75),
                    line1.length());
            }

            printf("\033[%d;%dH%s", m_line_level, 75, line1.c_str());
            ++m_line_level;

            if (!line2.empty()) {
                printf(
                    "\033[%d;%dH%s", m_line_level, 75, line2.c_str());
                ++m_line_level;
            }
        }

        printf("\033[%d;75H", m_line_level);
        fflush(stdout);
    }

private:
    int m_line_level = 5;
};

#endif // WITNESS_LOGGER_HPP
