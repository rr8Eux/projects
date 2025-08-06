import hashlib
import random
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

O = Point()

def mod_inv(a, p):
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        nm, neww = hm - lm * ratio, high - low * ratio
        lm, hm = nm, lm
        low, high = neww, low
    return lm % p

def point_add(P, Q):
    if P.is_infinite: return Q
    if Q.is_infinite: return P
    if P.x == Q.x:
        if P.y != Q.y: return O
        lam = ((3 * P.x ** 2 + a) * mod_inv(2 * P.y, p)) % p
    else:
        lam = ((Q.y - P.y) * mod_inv(Q.x - P.x, p)) % p
    x = (lam ** 2 - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p
    return Point(x, y)

def scalar_mult(k, P):
    if P.is_infinite or k == 0:
        return O
    result = O
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    while True:
        d = random.randint(1, n - 1)
        Q = scalar_mult(d, Point(Gx, Gy))
        if not Q.is_infinite:
            break
    return d, Q

def ecdsa_sign(private_key, message):
    e = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big') % n
    k = random.randint(1, n - 1)
    R = scalar_mult(k, Point(Gx, Gy))
    r = R.x % n
    if r == 0: raise ValueError("无效的随机数k导致r=0")
    s = (mod_inv(k, n) * (e + private_key * r)) % n
    return (r, s)

def ecdsa_verify(public_key, message, signature):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n): return False
    e_prime = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big') % n
    w = mod_inv(s, n)
    u1 = (e_prime * w) % n
    u2 = (r * w) % n
    P3 = point_add(scalar_mult(u1, Point(Gx, Gy)), scalar_mult(u2, public_key))
    return P3.x % n == r

if __name__ == "__main__":
    private_key, public_key = generate_keypair()
    print(f"私钥 (十六进制): {hex(private_key)}")
    print(f"公钥坐标: X={public_key.x}, Y={public_key.y}")

    test_message = "伪造中本聪的数字签名"
    print(f"\n原始消息:\n{test_message}")

    signature = ecdsa_sign(private_key, test_message)
    print(f"\n签名结果 (r, s): r={signature[0]:x}, s={signature[1]:x}")

    is_valid = ecdsa_verify(public_key, test_message, signature)
    print(f"\n签名验证结果: {'有效' if is_valid else '无效'}")

    tampered_msg = test_message[:-5] + "!!!"
    is_tampered_valid = ecdsa_verify(public_key, tampered_msg, signature)
    print(f"篡改后的消息验证结果: {'错误通过' if is_tampered_valid else '正确拒绝'}")