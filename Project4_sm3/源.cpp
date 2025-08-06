#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <bitset>
#include <random>
#include <iomanip>
#include <chrono>

using namespace std;

constexpr int SM3_BLOCK_SIZE = 512;
constexpr int SM3_DIGEST_SIZE = 256;
constexpr int SM3_ROUNDS = 64;

const uint32_t IV[8] = {
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E
};

inline uint32_t P0(uint32_t x) {
    return x ^ (x << 9) ^ (x << 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ (x << 15) ^ (x << 23);
}

inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | ((~x) & z);
}

inline uint32_t left_rotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

uint64_t bswap64(uint64_t value) {
    return ((value & 0x00000000000000FFULL) << 56) |
        ((value & 0x000000000000FF00ULL) << 40) |
        ((value & 0x0000000000FF0000ULL) << 24) |
        ((value & 0x00000000FF000000ULL) << 8) |
        ((value & 0x000000FF00000000ULL) >> 8) |
        ((value & 0x0000FF0000000000ULL) >> 24) |
        ((value & 0x00FF000000000000ULL) >> 40) |
        ((value & 0xFF00000000000000ULL) >> 56);
}

void pad_message(const uint8_t* msg, size_t msg_len, vector<uint8_t>& padded, size_t& padded_len) {
    size_t bit_length = msg_len * 8;
    padded.reserve(msg_len + 64);
    memcpy(padded.data(), msg, msg_len);
    padded.push_back(0x80);

    size_t total_bits = (msg_len + 1) * 8;
    size_t needed_bits = (448 - (total_bits % 512)) % 512;
    size_t needed_bytes = (needed_bits + 7) / 8;

    padded.insert(padded.end(), needed_bytes, 0x00);
    msg_len += needed_bytes;

    uint64_t bit_length_be = bswap64(static_cast<uint64_t>(bit_length));
    padded.resize(msg_len + sizeof(uint64_t));
    memcpy(padded.data() + msg_len, &bit_length_be, sizeof(uint64_t));
    padded_len = padded.size();
}

void generate_random_message(uint8_t* message, size_t length) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < length; ++i) {
        message[i] = static_cast<uint8_t>(dis(gen));
    }
}

void sm3_hash(const uint8_t* msg, size_t msg_len, vector<uint8_t>& hash_output) {
    vector<uint8_t> padded;
    size_t padded_len = 0;
    pad_message(msg, msg_len, padded, padded_len);

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    for (size_t i = 0; i <= padded_len - SM3_BLOCK_SIZE; i += SM3_BLOCK_SIZE) {
        if (i + SM3_BLOCK_SIZE > padded_len) {
            break;
        }

        uint32_t W[68];
        for (int j = 0; j < 16; ++j) {
            W[j] = (padded[i + 4 * j] << 24) |
                (padded[i + 4 * j + 1] << 16) |
                (padded[i + 4 * j + 2] << 8) |
                (padded[i + 4 * j + 3]);
        }
        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ P0(W[j - 15] ^ W[j - 1])) ^ P0(W[j - 14] ^ W[j - 2]);
        }

        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (int j = 0; j < SM3_ROUNDS; ++j) {
            uint32_t SS1 = left_rotate((left_rotate(A, 12) + E + F), 7);
            uint32_t SS2 = SS1 ^ left_rotate(A, 12);
            uint32_t TT1 = FF(A, B, C) + SS2 + GG(D, E, F) + W[j];
            uint32_t TT2 = GG(E, F, G) + SS1 + FF(D, E, F) + W[j + 4];
            D = C;
            C = left_rotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = F;
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    hash_output.resize(SM3_DIGEST_SIZE / 8);
    for (int i = 0; i < 8; ++i) {
        hash_output[i * 4] = (state[i] >> 24) & 0xFF;
        hash_output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash_output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash_output[i * 4 + 3] = state[i] & 0xFF;
    }
}

int main() {
    constexpr size_t MESSAGE_LENGTH = 1024;
    constexpr int ITERATIONS = 10;
    constexpr int BYTES_PER_LINE = 16;

    double total_time = 0.0;

    cout << fixed << setprecision(6);

    for (int i = 0; i < ITERATIONS; ++i) {
        vector<uint8_t> random_message(MESSAGE_LENGTH);
        generate_random_message(random_message.data(), MESSAGE_LENGTH);

        cout << "----------第" << i + 1 << "次加密----------" << endl;
        cout << "随机生成的消息: ";
        for (size_t j = 0; j < random_message.size(); ++j) {
            cout << hex << uppercase << static_cast<int>(random_message[j]);
            if ((j + 1) % BYTES_PER_LINE == 0) {
                cout << ' ';
            }
        }
        cout << dec << endl;

        auto start = chrono::high_resolution_clock::now();
        vector<uint8_t> hash;
        sm3_hash(random_message.data(), random_message.size(), hash);
        auto end = chrono::high_resolution_clock::now();

        chrono::duration<double, milli> duration = end - start;
        double time_taken = duration.count();

        cout << "SM3 哈希值: ";
        for (size_t j = 0; j < hash.size(); ++j) {
            cout << hex << uppercase << static_cast<int>(hash[j]);
            if ((j + 1) % BYTES_PER_LINE == 0) {
                cout << ' ';
            }
        }
        cout << dec << " 时间: " << time_taken << " ms" << endl;

        total_time += time_taken;
    }

    double average_time = total_time / ITERATIONS;
    cout << "==============================================================" << endl;
    cout << "执行 " << ITERATIONS << " 次SM3哈希的总用时为: " << total_time << " ms，平均时间为: " << average_time << " ms" << endl;

    return 0;
}