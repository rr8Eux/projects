#include <iostream>
#include <vector>
#include <sstream>
#include <cstring>
#include <string>
#include <bitset>
#include <random>
#include <iomanip>
#include <chrono>
#include <memory>
#include <algorithm>

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

struct MerkleNode {
    vector<uint8_t> hash;
    shared_ptr<MerkleNode> left;
    shared_ptr<MerkleNode> right;

    MerkleNode(const vector<uint8_t>& h) : hash(h), left(nullptr), right(nullptr) {}
};

shared_ptr<MerkleNode> buildMerkleTree(const vector<vector<uint8_t>>& leafHashes, int start, int end) {
    if (start == end) {
        return make_shared<MerkleNode>(leafHashes[start]);
    }
    int mid = start + (end - start) / 2;
    auto leftChild = buildMerkleTree(leafHashes, start, mid);
    auto rightChild = buildMerkleTree(leafHashes, mid + 1, end);

    vector<uint8_t> combined;
    combined.insert(combined.end(), leftChild->hash.begin(), leftChild->hash.end());
    combined.insert(combined.end(), rightChild->hash.begin(), rightChild->hash.end());
    vector<uint8_t> parentHash;
    sm3_hash(combined.data(), combined.size(), parentHash);

    auto parent = make_shared<MerkleNode>(parentHash);
    parent->left = leftChild;
    parent->right = rightChild;

    return parent;
}

vector<vector<uint8_t>> getExistenceProof(shared_ptr<MerkleNode> root, int index, const vector<vector<uint8_t>>& leafHashes) {
    vector<vector<uint8_t>> proof;
    shared_ptr<MerkleNode> current = root;
    int l = 0;
    int r = leafHashes.size() - 1;
    while (l != r) {
        int mid = l + (r - l) / 2;
        if (index <= mid) {
            proof.push_back(current->right->hash);
            current = current->left;
            r = mid;
        }
        else {
            proof.push_back(current->left->hash);
            current = current->right;
            l = mid + 1;
        }
    }
    return proof;
}

bool verifyExistenceProof(const vector<uint8_t>& rootHash, const vector<uint8_t>& leafHash, const vector<vector<uint8_t>>& proof) {
    vector<uint8_t> currentHash = leafHash;
    for (auto it = proof.rbegin(); it != proof.rend(); ++it) {
        vector<uint8_t> combined;
        combined.insert(combined.end(), currentHash.begin(), currentHash.end());
        combined.insert(combined.end(), it->begin(), it->end());
        vector<uint8_t> parentHash;
        sm3_hash(combined.data(), combined.size(), parentHash);
        currentHash = parentHash;
    }
    return currentHash == rootHash;
}

bool areHashesEqual(const vector<uint8_t>& a, const vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

bool findTargetHash(shared_ptr<MerkleNode> node, const vector<uint8_t>& targetHash, vector<vector<uint8_t>>& proofPath, bool& found) {
    if (!node) {
        return false;
    }

    if (!node->left && !node->right) {
        if (areHashesEqual(node->hash, targetHash)) {
            found = true;
            return true;
        }
        else {
            return false;
        }
    }

    bool leftExists = findTargetHash(node->left, targetHash, proofPath, found);
    bool rightExists = findTargetHash(node->right, targetHash, proofPath, found);

    if (found) {
        if (leftExists) {
            proofPath.push_back(node->right->hash);
            return true;
        }
        if (rightExists) {
            proofPath.push_back(node->left->hash);
            return true;
        }
    }
    else {
        return false;
    }

    return false;
}

bool getNonExistenceProof(shared_ptr<MerkleNode> root, const vector<uint8_t>& targetHash, vector<vector<uint8_t>>& proofPath) {
    bool found = false;
    bool exists = findTargetHash(root, targetHash, proofPath, found);
    if (exists) {
        proofPath.clear();
        return false;
    }
    else {
        return true;
    }
}

string bytesToHex(const vector<uint8_t>& bytes) {
    ostringstream oss;
    for (auto byte : bytes) {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

int main() {
    constexpr size_t MESSAGE_LENGTH = 32;
    constexpr size_t TOTAL_LEAVES = 100000;
    constexpr int ITERATIONS = 1;
    constexpr int BYTES_PER_LINE = 16;

    cout << fixed << setprecision(6);
    cout << "开始生成随机消息..." << endl;
    vector<uint8_t> messages(MESSAGE_LENGTH * TOTAL_LEAVES);
    generate_random_message(messages.data(), messages.size());
    cout << "随机消息生成完毕。" << endl;

    cout << "开始计算叶子节点的哈希值..." << endl;
    vector<vector<uint8_t>> leafHashes;
    leafHashes.reserve(TOTAL_LEAVES);
    for (size_t i = 0; i < TOTAL_LEAVES; ++i) {
        vector<uint8_t> hash;
        sm3_hash(&messages[i * MESSAGE_LENGTH], MESSAGE_LENGTH, hash);
        leafHashes.push_back(hash);
        if ((i + 1) % 1000 == 0) {
            cout << "已计算 " << (i + 1) << " / " << TOTAL_LEAVES << " 个叶子节点的哈希值。" << endl;
        }
    }
    cout << "所有叶子节点的哈希值计算完毕。" << endl;

    cout << "开始构建Merkle树..." << endl;
    auto merkleRoot = buildMerkleTree(leafHashes, 0, leafHashes.size() - 1);
    cout << "Merkle树构建完毕。根哈希值: ";
    for (auto byte : merkleRoot->hash) {
        cout << hex << uppercase << static_cast<int>(byte);
    }
    cout << dec << endl;

    cout << "生成存在性证明..." << endl;
    vector<vector<uint8_t>> existenceProof1 = getExistenceProof(merkleRoot, 0, leafHashes);
    vector<vector<uint8_t>> existenceProofN = getExistenceProof(merkleRoot, TOTAL_LEAVES - 1, leafHashes);
    cout << "第1个叶子节点的存在性证明生成完毕。" << endl;
    cout << "第10万个叶子节点的存在性证明生成完毕。" << endl;

    bool isValid1 = verifyExistenceProof(merkleRoot->hash, leafHashes[0], existenceProof1);
    bool isValidN = verifyExistenceProof(merkleRoot->hash, leafHashes[TOTAL_LEAVES - 1], existenceProofN);
    cout << "第1个叶子节点的存在性验证结果: " << (isValid1 ? "有效" : "无效") << endl;
    cout << "第10万个叶子节点的存在性验证结果: " << (isValidN ? "有效" : "无效") << endl;

    cout << "生成不存在性证明..." << endl;
    vector<uint8_t> targetHash(SM3_DIGEST_SIZE / 8, 0x00);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned int> dis(0, 255);
    generate(targetHash.begin(), targetHash.end(), [&]() { return static_cast<uint8_t>(dis(gen)); });
    string hashHex = bytesToHex(targetHash);
    cout << "目标哈希值为：" << hashHex << endl;
    vector<vector<uint8_t>> nonExistenceProof;
    bool exists = getNonExistenceProof(merkleRoot, targetHash, nonExistenceProof);
    if (!exists) {
        cout << "目标哈希值不存在于Merkle树中。" << endl;
    }
    else {
        cout << "目标哈希值存在于Merkle树中，无法生成不存在性证明。" << endl;
    }

    return 0;
}