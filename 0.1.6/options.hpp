#ifndef WITNESS_OPTIONS_HPP
#define WITNESS_OPTIONS_HPP

#include "utilities.hpp"

class options {
public:
    options(ut::str2str& argsstr, ut::str2num& argsnum)
        : m_single_target(
            argsstr["pos1"].length()
        )
        , m_single_proxy(
            argsstr["-p"].length()
        )
        , m_proxies_listed(
            argsstr["-pl"].length()
        )
        , m_targets_listed(
            argsstr["-ul"].length()
        )
        , m_noloop(
            argsstr.find("-noloop") != argsstr.end()
        )
        , m_target(
            argsstr["pos1"]
        )
        , m_cx(
            argsstr.find("-cx") != argsstr.end()
        )
        , m_proxy(
            argsstr["-p"]
        )
        , m_iran(
            argsstr.find("-iran") != argsstr.end()
        )
        , m_num_threads(
            argsnum["-nt"]
        )
        , m_interv_fire(
            argsnum["-del"]
        )
        , m_proxies(
            argsstr["-pl"]
        )
        , m_targets(
            argsstr["-ul"]
        )
    {
        if (m_num_threads == 0) {
            m_num_threads = 1;
        }
    }

    void validate() {
        if (m_single_proxy && m_proxies_listed) {
            throw ut::except(
                "single proxie and proxies listed?"
            );
        }

        if (m_single_target && m_targets_listed) {
            throw ut::except(
                "single target and targets listed?"
            );
        }

        if (m_num_threads == 0) {
            throw ut::except(
                "0 threads = program does nothing"
            );
        }

        if (m_interv_fire > 30) {
            throw ut::except(
                "strike interval greater than "
                "30 wont rape the game"
            );
        }

        if (m_proxies_listed && m_proxies.empty()) {
            throw ut::except(
                "the proxy list filename "
                "can't be empty!"
            );
        }

        if (m_targets_listed && m_targets.empty()) {
            throw ut::except(
                "the target list filename "
                "can't be empty!"
            );
        }
    }

    bool m_single_target;
    bool m_single_proxy;
    bool m_proxies_listed;
    bool m_targets_listed;
    bool m_noloop;
    std::string m_target;
    bool m_cx;
    std::string m_proxy;
    bool m_iran;
    int  m_num_threads;
    int  m_interv_fire;
    std::string m_proxies;
    std::string m_targets;
};

#endif // WITNESS_OPTIONS_HPP
