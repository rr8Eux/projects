#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <chrono>
#include "functions.h"
#include <immintrin.h>

using namespace std;
using namespace std::chrono;

const uint8_t SBox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

constexpr uint32_t Fk[4] = {
    0xA3B1BAC6,
    0x56AA3350,
    0x677D9197,
    0xB27022DC
};

uint32_t T_table[256][4];

void init_T_table() {
    for (int i = 0; i < 256; ++i) {
        uint32_t word = static_cast<uint32_t>(i) << 24;
        word = nonlinear_transform(word);
        word = linear_transform(word);
        for (int j = 0; j < 4; ++j) {
            T_table[i][j] = (word >> (8 * (3 - j))) & 0xFF;
        }
    }
}

uint32_t left_rotate(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

void key_expansion_avx(const uint8_t key[16], uint32_t round_keys[32]) {
    __m128i key_vec = _mm_setr_epi32(0, 0, 0, 0);
    for (int i = 0; i < 4; ++i) {
        key_vec = _mm_insert_epi32(key_vec,
            static_cast<uint32_t>(key[i]) << 24 |
            static_cast<uint32_t>(key[i + 4]) << 16 |
            static_cast<uint32_t>(key[i + 8]) << 8 |
            static_cast<uint32_t>(key[i + 12]), i);
    }
    round_keys[0] = _mm_extract_epi32(key_vec, 0);
    for (int i = 1; i < 32; ++i) {
        __m128i rotated = _mm_or_si128(_mm_slli_epi32(key_vec, 8), _mm_srli_epi32(key_vec, 24));
        if (i % 4 == 0) {
            switch (i / 4 - 1) {
            case 0: rotated = _mm_xor_si128(rotated, _mm_set1_epi32(Fk[0])); break;
            case 1: rotated = _mm_xor_si128(rotated, _mm_set1_epi32(Fk[1])); break;
            case 2: rotated = _mm_xor_si128(rotated, _mm_set1_epi32(Fk[2])); break;
            case 3: rotated = _mm_xor_si128(rotated, _mm_set1_epi32(Fk[3])); break;
            default: /* 处理异常情况 */ break;
            }
        }
        key_vec = rotated;
        round_keys[i] = _mm_extract_epi32(key_vec, 0);
    }
}

__m128i round_function_avx(__m128i input, __m128i round_key) {
    __m128i output = _mm_xor_si128(input, round_key);

    uint32_t words[4];
    _mm_storeu_si128((__m128i*)words, output);

    for (int i = 0; i < 4; ++i) {
        words[i] = nonlinear_transform(words[i]);
    }

    __m128i transformed = _mm_loadu_si128((__m128i*)words);

    uint32_t linearWords[4];
    _mm_storeu_si128((__m128i*)linearWords, transformed);

    for (int i = 0; i < 4; ++i) {
        linearWords[i] = linear_transform(linearWords[i]);
    }

    __m128i result = _mm_loadu_si128((__m128i*)linearWords);

    return result;
}

void sm4_encrypt_optimized(const uint8_t plaintext[16], const uint8_t key[16], uint8_t ciphertext[16]) {
    uint32_t round_keys[32];
    key_expansion_avx(key, round_keys);
    __m128i data = _mm_loadu_si128((__m128i*)plaintext);
    for (int r = 0; r < 32; ++r) {
        __m128i round_key = _mm_set_epi32(round_keys[r], round_keys[r], round_keys[r], round_keys[r]);
        data = round_function_avx(data, round_key);
    }
    _mm_storeu_si128((__m128i*)ciphertext, data);
}

int main() {
    init_T_table();
    srand(static_cast<unsigned int>(time(nullptr)));

    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    };
    const int iterations = 10;
    double total_time = 0.0;

    for (int i = 0; i < iterations; ++i) {
        uint8_t plaintext[16];
        for (int j = 0; j < 16; ++j) {
            plaintext[j] = static_cast<uint8_t>(rand() % 256);
        }

        auto start = high_resolution_clock::now();
        uint8_t ciphertext[16];
        sm4_encrypt_optimized(plaintext, key, ciphertext);
        auto end = high_resolution_clock::now();

        chrono::duration<double, milli> duration = end - start;
        total_time += duration.count();
    }

    double average_time = total_time / iterations;
    cout << "总加密时间: " << total_time << " ms" << endl;
    cout << "平均加密时间: " << average_time << " ms" << endl;

    return 0;
}