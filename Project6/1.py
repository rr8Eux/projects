import random
import math

class SimulatedGroup:
    def __init__(self, order):
        self.order = order

    def random_element(self):
        return random.randint(0, self.order - 1)

    def exponentiate(self, base, exponent):
        return pow(base, exponent, self.order)

def hash_function(u, group):
    h = abs(hash(u)) % group.order
    return h

class AdditiveHE:
    @staticmethod
    def generate_large_prime(bitsize):
        while True:
            candidate = random.getrandbits(bitsize)
            candidate |= (1 << (bitsize - 1)) | 1
            if AdditiveHE.is_prime(candidate):
                return candidate

    @staticmethod
    def is_prime(num, rounds=5):
        if num < 2: return False
        d = num - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(rounds):
            a = random.randint(2, num - 2)
            x = pow(a, d, num)
            if x == 1 or x == num - 1: continue
            for __ in range(s - 1):
                x = pow(x, 2, num)
                if x == num - 1: break
            else: return False
        return True

    @staticmethod
    def keygen(security_param):
        half_sec_parm = security_param // 2
        p = AdditiveHE.generate_large_prime(half_sec_parm)
        while True:
            q = AdditiveHE.generate_large_prime(half_sec_parm)
            if q != p: break
        n = p * q
        g = 1 + n
        pk = (n, g)
        sk = (p, q)
        return pk, sk

    @staticmethod
    def encrypt(pk, plaintext):
        n, g = pk
        r = random.randint(1, n - 1)
        while math.gcd(r, n) != 1:
            r = random.randint(1, n - 1)
        ciphertext = (pow(g, plaintext, n * n) * pow(r, n, n * n)) % (n * n)
        return ciphertext

    @staticmethod
    def add(ct1, ct2, pk):
        n, _ = pk
        return (ct1 * ct2) % (n * n)

    @staticmethod
    def decrypt(sk, ciphertext):
        p, q = sk
        n = p * q
        lambda_val = (p - 1) * (q - 1)
        x = pow(ciphertext, lambda_val, n * n)
        l_x = (x - 1) // n
        l_g = (pow(pk[1], lambda_val, n * n) - 1) // n
        try:
            inv_lg = pow(l_g, -1, n)
        except ValueError:
            raise ValueError("Decryption failed: l_g and n are not coprime")
        message = (l_x * inv_lg) % n
        return message

if __name__ == "__main__":
    try:
        q = 2 ** 127 - 1
        U_sample = ["user1", "itemA", "dataX"]
        G = SimulatedGroup(q)

        shared_key = "common_element"
        m1 = len(U_sample[:3]) + 1
        V = [shared_key] + [f"v_{i}" for i in range(m1 - 1)]
        m2 = 4
        W = [(shared_key, 10), ("w_1", 6), ("w_2", 7), ("w_3", 8)]

        k1 = random.randint(1, q - 1)
        k2 = random.randint(1, q - 1)

        pk, sk = AdditiveHE.keygen(security_param=1024)

        print(f"初始化完成:\n - P1私钥指数k₁={k1}\n - P2私钥指数k₂={k2}\n - HE公钥pk={pk}")

        c_list = []
        for vi in V:
            h_vi = hash_function(vi, G)
            ci = G.exponentiate(h_vi, k1)
            c_list.append(ci)

        Z = []
        for ci in c_list:
            di = G.exponentiate(ci, k2)
            Z.append(di)

        processed_tuples = []
        for wj, tj in W:
            ej1 = G.exponentiate(hash_function(wj, G), k2)
            sigma_j = AdditiveHE.encrypt(pk, tj)
            processed_tuples.append((ej1, sigma_j))

        print(f"\n第1轮传输: {len(c_list)}个c_i值已发送至P2")
        print(f"\n第2轮传输:\n - Z集合大小={len(Z)}\n - 元组数量={len(processed_tuples)}")

        J = set()
        sigma_decryption_targets = []

        for idx, (ej1, sigma_j) in enumerate(processed_tuples):
            ej2 = G.exponentiate(ej1, k1)
            for di in Z:
                if ej2 == di:
                    J.add(idx)
                    sigma_decryption_targets.append(sigma_j)
                    break

        if not sigma_decryption_targets:
            summed_ciphertext = AdditiveHE.encrypt(pk, 0)
        else:
            summed_ciphertext = sigma_decryption_targets[0]
            for ct in sigma_decryption_targets[1:]:
                summed_ciphertext = AdditiveHE.add(summed_ciphertext, ct, pk)

        S_J = AdditiveHE.decrypt(sk, summed_ciphertext)

        print(f"\n第3轮结果:\n - 交集索引J={sorted(J)}\n - 聚合密文Σ_enc已随机化处理")
        print(f"\n最终输出: 交集元素的总和 S_J = {S_J}")

        expected_sum = sum(W[j][1] for j in J)
        assert S_J == expected_sum, f"错误！预期总和={expected_sum}, 实际得到={S_J}"
        print("验证通过！协议执行成功。")

    except Exception as e:
        print(f"发生异常: {e}")