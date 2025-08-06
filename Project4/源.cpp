#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <bitset>
#include <random>
#include <iomanip>
#include <chrono>

using namespace std;

const int SM3_BLOCK_SIZE = 512;
const int SM3_DIGEST_SIZE = 256;
const int SM3_ROUNDS = 64;

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

// 辅助函数P0和P1
inline uint32_t P0(uint32_t x) {
    return x ^ (x << 9) ^ (x << 17);
}

inline uint32_t P1(uint32_t x) {
    return x ^ (x << 15) ^ (x << 23);
}

// 逻辑函数FF和GG
inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | ((~x) & z);
}

// 循环左移函数
uint32_t left_rotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

// 填充函数
vector<uint8_t> pad_message(const vector<uint8_t>& msg) {
    vector<uint8_t> padded = msg;
    size_t bit_length = msg.size() * 8;
    padded.push_back(0x80);
    while ((padded.size() * 8) % SM3_BLOCK_SIZE != 448) {
        padded.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back((bit_length >> (i * 8)) & 0xFF);
    }
    return padded;
}

// 主要SM3函数
vector<uint8_t> sm3_hash(const vector<uint8_t>& msg) {
    vector<uint8_t> padded = pad_message(msg);
    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));
    for (size_t i = 0; i < padded.size(); i += 64) {
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
        // 压缩函数
        uint32_t A, B, C, D, E, F, G, H;
        A = state[0];
        B = state[1];
        C = state[2];
        D = state[3];
        E = state[4];
        F = state[5];
        G = state[6];
        H = state[7];
        for (int j = 0; j < SM3_ROUNDS; ++j) {
            uint32_t SS1 = left_rotate((left_rotate(A, 12) + E + F), 7);
            uint32_t SS2 = SS1 ^ left_rotate(A, 12);
            uint32_t TT1 = (FF(A, B, C) + SS2 + GG(D, E, F) + W[j]);
            uint32_t TT2 = (GG(E, F, G) + SS1 + FF(D, E, F) + W[j + 4]);
            D = C;
            C = left_rotate(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = F;
            F = E;
            E = P0(TT2);
        }
        // 更新状态向量
        state[0] ^= A ^ state[0];
        state[1] ^= B ^ state[1];
        state[2] ^= C ^ state[2];
        state[3] ^= D ^ state[3];
        state[4] ^= E ^ state[4];
        state[5] ^= F ^ state[5];
        state[6] ^= G ^ state[6];
        state[7] ^= H ^ state[7];
    }
    // 输出哈希值
    vector<uint8_t> hash;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            hash.push_back((state[i] >> (24 - j * 8)) & 0xFF);
        }
    }
    return hash;
}

// 生成随机消息
vector<uint8_t> generate_random_message(size_t length) {
    vector<uint8_t> message(length);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < length; ++i) {
        message[i] = static_cast<uint8_t>(dis(gen));
    }
    return message;
}

int main() {
    size_t message_length = 1024;

    double total_time = 0.0;
    int iterations = 10;

    for (int i = 0; i < iterations; ++i) {
        vector<uint8_t> random_message = generate_random_message(message_length);
        cout << "----------第" << i + 1 << "次加密----------" << endl;
        cout << "随机生成的消息: ";
        for (auto byte : random_message) {
            printf("%02X", byte);
        }
        cout << endl;

        auto start = chrono::high_resolution_clock::now();
        vector<uint8_t> hash = sm3_hash(random_message);
        auto end = chrono::high_resolution_clock::now();

        chrono::duration<double, milli> duration = end - start;
        double time_taken = duration.count();

        cout << "第 " << i + 1 << " 次SM3哈希值: ";
        for (auto byte : hash) {
            printf("%02X", byte);
        }
        cout << " 时间: " << fixed << setprecision(6) << time_taken << " 秒" << endl;
        total_time += time_taken;
    }

    double average_time = total_time / iterations;
    cout << "=======================================================================" << endl;
    cout << "执行 " << iterations << " 次SM3哈希的总用时为：" << fixed << setprecision(6) << total_time << " 毫秒" << "，平均时间为: " << fixed << setprecision(6) << average_time << " 毫秒" << endl;

    return 0;
}