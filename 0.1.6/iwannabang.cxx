#include <signal.h>

#include "options.hpp"
#include "shahed.hpp"
#include "witness.hpp"

#include <iostream>
#include <deque>

inline std::deque<witness> witnesses;

void leave(int signum = 0) {
    try {
        for (witness& love: witnesses) {
            love.leave_target();
        }
    } catch (...) {
    }
    leave_ui();
}

void init(ut::str2str map0, ut::str2num map1) {
    options opts(map0, map1);

    try {
        opts.validate();
    } catch (ut::except e) {
        std::cout << e.what() << '\n';
        exit(0);
    }

    if (!opts.m_cx) {
        init_ui();
    }

    signal(SIGINT, leave), signal(SIGTERM,leave);
    signal(SIGSEGV,leave), signal(SIGABRT,leave);

    if (opts.m_single_target &&
        !opts.m_single_proxy &&
        !opts.m_proxies_listed)
    {
        witness& love = witnesses.emplace_back();
        love.set_options(opts);
    } else if (
        opts.m_targets_listed &&
        !opts.m_single_proxy &&
        !opts.m_proxies_listed
    ) {
        ut::string_set targets
            = ut::list_loader_v1(opts.m_targets);

        for (const std::string& target: targets) {
            witness& love
                = witnesses.emplace_back();
            love.set_options(opts);
            love.set_target(target);
        }
    }

    for (witness& love: witnesses) {
        love.launch_attack();
        love.async_loop(opts.m_num_threads);
    }

    for (witness& love: witnesses) {
        love.async_wait();
    }
}

int main(int argc, char* argv[]) {
    init(
        ut::argv_parser_v1(argc, argv),
        ut::argv_parser_v2(argc, argv)
    );
    leave();
}
