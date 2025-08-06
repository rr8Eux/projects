import hashlib
import random
import os
from dataclasses import dataclass

p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)
n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF720FEAD67065DCB07CF64D7D0845351D3C9FD5', 16)

@dataclass
class Point:
    x: int = -1
    y: int = -1
    is_infinite: bool = False

    def __post_init__(self):
        if self.x == -1 and self.y == -1:
            self.is_infinite = True
        else:
            self.is_infinite = False

def mod_inv(a, m):
    try:
        g, x, y = extended_gcd(a, m)
        if g != 1:
            return None
        return x % m
    except Exception as e:
        print(f"计算模逆失败: a={a}, m={m}, error={str(e)}")
        return None

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def point_add(P, Q):
    if P.is_infinite:
        return Q
    if Q.is_infinite:
        return P
    if P.x == Q.x and P.y != Q.y:
        return Point()
    if P.x == Q.x and P.y == Q.y:
        if P.y == 0:
            return Point()
        numerator = (3 * P.x ** 2 + a) % p
        denominator = (2 * P.y) % p
        inv_denominator = mod_inv(denominator, p)
        if inv_denominator is None:
            raise ValueError("无法计算切线斜率（分母不可逆）")
        lam = (numerator * inv_denominator) % p
    else:
        numerator = (Q.y - P.y) % p
        denominator = (Q.x - P.x) % p
        if denominator == 0:
            raise ValueError("无法计算弦斜率（分母为零）")
        inv_denominator = mod_inv(denominator, p)
        if inv_denominator is None:
            raise ValueError("无法计算弦斜率（分母不可逆）")
        lam = (numerator * inv_denominator) % p
    x = (lam ** 2 - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p
    return Point(x, y)

def scalar_mult(k, P):
    result = Point()
    addend = P
    while k > 0:
        if k % 2 == 1:
            new_result = point_add(result, addend)
            if new_result.is_infinite:
                break
            result = new_result
        addend = point_add(addend, addend)
        if addend.is_infinite:
            break
        k >>= 1
    return result

def generate_keypair():
    attempts = 0
    max_attempts = 100
    while attempts < max_attempts:
        d = random.randint(1, n - 1)
        Q = scalar_mult(d, Point(Gx, Gy))
        if not Q.is_infinite and Q.x != -1 and Q.y != -1:
            return d, Q
        attempts += 1
    raise RuntimeError("无法生成有效的密钥对")

def bytes_to_int(bytes_data):
    return sum(b << (i * 8) for i, b in enumerate(bytes_data)) % p

def sign_ecdsa(private_key, message):
    z = bytes_to_int(hashlib.sha256(message).digest())
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % n
        try:
            R = scalar_mult(k, Point(Gx, Gy))
            if R.is_infinite:
                continue
            r = R.x % n
            s = (z + r * private_key) * mod_inv(k, n) % n
            if s is None:
                continue
            if 0 < r < n and 0 < s < n:
                return r, s
        except ValueError:
            continue

def verify_ecdsa(public_key, message, signature):
    r, s = signature
    if not (0 < r < n and 0 < s < n):
        return False
    z = bytes_to_int(hashlib.sha256(message).digest())
    try:
        w = mod_inv(s, n)
        if w is None:
            return False
        u1 = (z * w) % n
        u2 = (r * w) % n
        X = point_add(scalar_mult(u1, Point(Gx, Gy)), scalar_mult(u2, public_key))
        return X.x == r
    except ValueError:
        return False

if __name__ == "__main__":
    try:
        private_key, public_key = generate_keypair()
        print("已成功生成密钥对:")
        print(f"私钥 (十进制): {private_key}")
        print(f"公钥坐标 (Qx, Qy): ({hex(public_key.x)[2:]}, {hex(public_key.y)[2:]})")

        message = "伪造中本聪的数字签名".encode('utf-8')
        print("\n--------------------开始签名流程--------------------")
        print(f"待签名原始消息: {message.decode('utf-8')}")

        r, s = sign_ecdsa(private_key, message)
        print(f"\n成功生成数字签名!")
        print(f"签名值 r: {r}")
        print(f"签名值 s: {s}")

        print("\n正在验证签名有效性...")
        is_valid = verify_ecdsa(public_key, message, (r, s))
        print(f"该签名是否有效？ {'✓ 有效' if is_valid else '✗ 无效'}")
    except Exception as e:
        print(f"程序运行出错: {str(e)}")