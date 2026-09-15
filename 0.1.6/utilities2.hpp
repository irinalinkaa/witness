#ifndef WITNESS_UTILITIES2_HPP
#define WITNESS_UTILITIES2_HPP

#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace ut {

template <size_t fixed_size = 65535>
struct buffer {
    static_assert(fixed_size <= 65535);

    std::array<uint8_t, fixed_size> data{};
    uint16_t length = 0;

    constexpr size_t size() const noexcept {
        return length;
    }

    constexpr size_t capacity() const noexcept {
        return fixed_size;
    }

    constexpr bool empty() const noexcept {
        return length == 0;
    }

    constexpr bool full() const noexcept {
        return length == fixed_size;
    }

    uint8_t* begin() noexcept {
        return data.data();
    }

    const uint8_t* begin() const noexcept {
        return data.data();
    }

    uint8_t* end() noexcept {
        return data.data() + length;
    }

    const uint8_t* end() const noexcept {
        return data.data() + length;
    }

    uint8_t& operator[](size_t index) noexcept {
        return data[index];
    }

    const uint8_t& operator[](size_t index) const noexcept {
        return data[index];
    }

    void clear() noexcept {
        length = 0;
    }

    void resize(size_t new_length) {
        if (new_length > fixed_size) {
            throw std::length_error("buffer capacity exceeded");
        }

        length = static_cast<uint16_t>(new_length);
    }

    void reserve(size_t amount) {
        if (amount > fixed_size) {
            throw std::length_error("buffer capacity exceeded");
        }
    }

    void push(uint8_t byte) {
        if (length == fixed_size) {
            throw std::length_error("buffer capacity exceeded");
        }

        data[length++] = byte;
    }

    void append(const void* src, size_t amount) {
        if (amount > fixed_size - length) {
            throw std::length_error("buffer capacity exceeded");
        }

        std::memcpy(
            data.data() + length,
            src,
            amount
        );

        length = static_cast<uint16_t>(length + amount);
    }

    template <size_t N>
    void append(const std::array<uint8_t, N>& src) {
        append(src.data(), N);
    }

    void append(std::string_view src) {
        append(src.data(), src.size());
    }

    uint8_t* data_ptr() noexcept {
        return data.data();
    }

    const uint8_t* data_ptr() const noexcept {
        return data.data();
    }
};

using bigint = BIGNUM*;

inline bigint p25519() {
    bigint p = BN_new();

    if (!p ||
        BN_one(p) != 1 ||
        BN_lshift(p, p, 255) != 1 ||
        BN_sub_word(p, 19) != 1) {

        BN_free(p);
        return nullptr;
    }

    return p;
}

inline std::array<uint8_t, 32> bigint2arr(const bigint value) {
    if (!value) {
        throw std::invalid_argument("null bigint");
    }

    std::array<uint8_t, 32> result{};

    if (BN_bn2lebinpad(
            value,
            result.data(),
            static_cast<int>(result.size())
        ) != static_cast<int>(result.size())) {

        throw std::runtime_error(
            "failed converting bigint to key"
        );
    }

    return result;
}

inline bool mod_p(bigint a, BN_CTX* ctx) {
    if (!a || !ctx) {
        return false;
    }

    bigint p = p25519();

    if (!p) {
        return false;
    }

    const bool result =
        BN_nnmod(a, a, p, ctx) == 1;

    BN_free(p);

    return result;
}


inline uint32_t rotl32(
    uint32_t x,
    unsigned length
) noexcept {
    length &= 31;

    return (x << length) |
           (x >> ((32 - length) & 31));
}

inline uint32_t u32le(
    const uint8_t* p
) noexcept {
    return
        static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

inline bigint x25519(
    const std::array<uint8_t, 32>& scalar,
    const std::array<uint8_t, 32>& u,
    BN_CTX* /*ctx*/
) {
    EVP_PKEY* private_key =
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519,
            nullptr,
            scalar.data(),
            scalar.size()
        );

    if (!private_key) {
        return nullptr;
    }

    EVP_PKEY* public_key =
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            nullptr,
            u.data(),
            u.size()
        );

    if (!public_key) {
        EVP_PKEY_free(private_key);
        return nullptr;
    }

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(private_key, nullptr);

    if (!ctx) {
        EVP_PKEY_free(public_key);
        EVP_PKEY_free(private_key);
        return nullptr;
    }

    std::array<uint8_t, 32> shared{};

    size_t length = shared.size();

    bool success = false;

    if (EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_derive_set_peer(ctx, public_key) > 0 &&
        EVP_PKEY_derive(
            ctx,
            shared.data(),
            &length
        ) > 0 &&
        length == shared.size()) {

        success = true;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    if (!success) {
        return nullptr;
    }

    return BN_lebin2bn(
        shared.data(),
        static_cast<int>(shared.size()),
        nullptr
    );
}

inline std::array<uint8_t, 32> x25519_base(
    const std::array<uint8_t, 32>& scalar,
    BN_CTX* /*ctx*/
) {
    std::array<uint8_t, 32> result{};

    EVP_PKEY* key =
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519,
            nullptr,
            scalar.data(),
            scalar.size()
        );

    if (!key) {
        return result;
    }

    size_t length = result.size();

    if (EVP_PKEY_get_raw_public_key(
            key,
            result.data(),
            &length
        ) != 1 ||
        length != result.size()) {

        result.fill(0);
    }

    EVP_PKEY_free(key);

    return result;
}

inline std::array<uint8_t, 64> chacha_block(
    const std::array<uint8_t, 32>& key,
    uint32_t counter,
    const std::array<uint8_t, 12>& nonce
) {
    std::array<uint32_t, 16> x = {
        0x61707865u,
        0x3320646eu,
        0x79622d32u,
        0x6b206574u
    };

    for (size_t i = 0; i < 8; ++i) {
        x[4 + i] =
            u32le(key.data() + i * 4);
    }

    x[12] = counter;
    x[13] = u32le(nonce.data());
    x[14] = u32le(nonce.data() + 4);
    x[15] = u32le(nonce.data() + 8);

    const auto initial = x;

    auto qr = [&x](
        size_t a,
        size_t b,
        size_t c,
        size_t d
    ) noexcept {
        x[a] += x[b];
        x[d] = rotl32(x[d] ^ x[a], 16);

        x[c] += x[d];
        x[b] = rotl32(x[b] ^ x[c], 12);

        x[a] += x[b];
        x[d] = rotl32(x[d] ^ x[a], 8);

        x[c] += x[d];
        x[b] = rotl32(x[b] ^ x[c], 7);
    };

    for (int i = 0; i < 10; ++i) {
        qr(0, 4, 8, 12);
        qr(1, 5, 9, 13);
        qr(2, 6, 10, 14);
        qr(3, 7, 11, 15);

        qr(0, 5, 10, 15);
        qr(1, 6, 11, 12);
        qr(2, 7, 8, 13);
        qr(3, 4, 9, 14);
    }

    std::array<uint8_t, 64> output{};

    for (size_t i = 0; i < 16; ++i) {
        const uint32_t word =
            x[i] + initial[i];

        output[i * 4 + 0] =
            static_cast<uint8_t>(word);

        output[i * 4 + 1] =
            static_cast<uint8_t>(word >> 8);

        output[i * 4 + 2] =
            static_cast<uint8_t>(word >> 16);

        output[i * 4 + 3] =
            static_cast<uint8_t>(word >> 24);
    }

    return output;
}

template <size_t fixed_size>
inline void chacha20(
    buffer<fixed_size>& output,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    const uint8_t* input,
    size_t input_length
) {
    if (input_length > fixed_size) {
        throw std::length_error(
            "chacha20 output buffer too small"
        );
    }

    output.length =
        static_cast<uint16_t>(input_length);

    size_t offset = 0;
    uint32_t counter = 0;

    while (offset < input_length) {
        const auto keystream =
            chacha_block(
                key,
                counter++,
                nonce
            );

        const size_t length =
            std::min(
                size_t{64},
                input_length - offset
            );

        for (size_t i = 0; i < length; ++i) {
            output[offset + i] =
                input[offset + i] ^
                keystream[i];
        }

        offset += length;
    }
}

template <size_t fixed_size>
inline void chacha20(
    buffer<fixed_size>& output,
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    std::string_view input
) {
    chacha20(
        output,
        key,
        nonce,
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size()
    );
}

template <size_t length>
inline std::array<uint8_t, length> random_bytes() {
    static_assert(
        length <= std::numeric_limits<int>::max()
    );

    std::array<uint8_t, length> result{};

    if constexpr (length > 0) {
        if (RAND_bytes(
                result.data(),
                static_cast<int>(length)
            ) != 1) {

            throw std::runtime_error(
                "RAND_bytes failed"
            );
        }
    }

    return result;
}

template <size_t fixed_size, typename... Parts>
inline void concat(
    buffer<fixed_size>& output,
    const Parts&... parts
) {
    output.clear();

    auto append = [&output](const auto& part) {
        output.append(
            part.data(),
            part.size()
        );
    };

    (append(parts), ...);
}

inline uint8_t hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }

    throw std::invalid_argument(
        "bad hex character"
    );
}

template <size_t fixed_size = 65535>
inline buffer<fixed_size> from_hex(
    std::string_view input
) {
    if (input.size() & 1) {
        throw std::invalid_argument(
            "bad hex string length"
        );
    }

    buffer<fixed_size> output;

    const size_t bytes = input.size() / 2;

    if (bytes > fixed_size) {
        throw std::length_error(
            "hex output exceeds buffer capacity"
        );
    }

    for (size_t i = 0; i < bytes; ++i) {
        output.push(
            static_cast<uint8_t>(
                (hex_value(input[i * 2]) << 4) |
                hex_value(input[i * 2 + 1])
            )
        );
    }

    return output;
}

inline std::array<uint8_t, 12> chacha_nonce(
    const std::array<uint8_t, 8>& nonce8
) {
    std::array<uint8_t, 12> result{};

    std::memcpy(
        result.data() + 4,
        nonce8.data(),
        8
    );

    return result;
}

inline std::array<uint8_t, 8> counter_nonce(
    uint64_t counter,
    bool sc = false
) {
    std::array<uint8_t, 8> nonce{};

    for (size_t i = 0; i < 8; ++i) {
        nonce[i] =
            static_cast<uint8_t>(counter);

        counter >>= 8;
    }

    if (sc) {
        nonce[7] |= 0x80;
    }

    return nonce;
}

inline std::array<uint8_t, 32> sha256(
    std::string_view data
) {
    SHA256_CTX ctx;
    std::array<uint8_t, 32> digest{};

    if (SHA256_Init(&ctx) != 1 ||
        SHA256_Update(
            &ctx,
            data.data(),
            data.size()
        ) != 1 ||
        SHA256_Final(
            digest.data(),
            &ctx
        ) != 1) {

        throw std::runtime_error(
            "sha256 failed"
        );
    }

    return digest;
}

template <size_t length>
inline void sha256_update(
    SHA256_CTX& ctx,
    const std::array<uint8_t, length>& data
) {
    if (SHA256_Update(
            &ctx,
            data.data(),
            data.size()
        ) != 1) {

        throw std::runtime_error(
            "sha256 update failed"
        );
    }
}

template <size_t fixed_size>
inline void sha256_update(
    SHA256_CTX& ctx,
    const buffer<fixed_size>& data
) {
    if (SHA256_Update(
            &ctx,
            data.data.data(),
            data.size()
        ) != 1) {

        throw std::runtime_error(
            "sha256 update failed"
        );
    }
}

inline void sha256_update(
    SHA256_CTX& ctx,
    std::string_view data
) {
    if (SHA256_Update(
            &ctx,
            data.data(),
            data.size()
        ) != 1) {

        throw std::runtime_error(
            "sha256 update failed"
        );
    }
}

template <typename... Parts>
inline std::array<uint8_t, 32> sha256(
    const Parts&... parts
) {
    SHA256_CTX ctx;
    std::array<uint8_t, 32> digest{};

    if (SHA256_Init(&ctx) != 1) {
        throw std::runtime_error(
            "sha256 init failed"
        );
    }

    (sha256_update(ctx, parts), ...);

    if (SHA256_Final(
            digest.data(),
            &ctx
        ) != 1) {

        throw std::runtime_error(
            "sha256 final failed"
        );
    }

    return digest;
}

} // namespace ut

#endif // WITNESS_UTILITIES2_HPP
