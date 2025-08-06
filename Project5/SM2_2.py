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
    if P.is_infinite:
        return Q
    if Q.is_infinite:
        return P
    if P.x == Q.x:
        if P.y != Q.y:
            return Point(-1, -1, True)
        lam = ((3 * P.x ** 2 + a) * mod_inv(2 * P.y, p)) % p
    else:
        lam = ((Q.y - P.y) * mod_inv(Q.x - P.x, p)) % p
    x = (lam ** 2 - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p
    return Point(x, y)

def scalar_mult(k, P):
    if P.is_infinite or k == 0:
        return Point(-1, -1, True)
    result = Point(-1, -1, True)
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

O = Point()

def generate_keypair():
    while True:
        d = random.randint(1, n - 1)
        Q = scalar_mult(d, Point(Gx, Gy))
        if not Q.is_infinite:
            break
    return d, Q

def sign(private_key, message):
    k = random.randint(1, n - 1)
    R = scalar_mult(k, Point(Gx, Gy))
    if R.is_infinite:
        return None
    e = hashlib.sha256(message.encode()).hexdigest()[:64]
    e = int(e, 16) % n
    s = (mod_inv((k % n), n) * (e + private_key % n)) % n
    return (R, s)

def verify(public_key, message, signature):
    R, s = signature
    if R.is_infinite or s < 1 or s > n - 1:
        return False
    e = hashlib.sha256(message.encode()).hexdigest()[:64]
    e = int(e, 16) % n
    w = mod_inv(s % n, n)
    u1 = (e * w) % n
    u2 = (s * w) % n
    X = (u1 * Gx + u2 * public_key.x) % p
    Y = (u1 * Gy + u2 * public_key.y) % p
    return R == Point(X, Y)

# Alice和Bob生成密钥对并签名消息
alice_private, alice_public = generate_keypair()
bob_private, bob_public = generate_keypair()

message1 = "Message from Alice"
message2 = "Message from Bob"

alice_signature = sign(alice_private, message1)
bob_signature = sign(bob_private, message2)

print("Alice 的签名：", alice_signature)
print("Bob 的签名：", bob_signature)

# 推导Alice的私钥
e1 = hashlib.sha256(message1.encode()).hexdigest()[:64]
e1 = int(e1, 16) % n
R1, s1 = alice_signature
k1 = mod_inv((s1 % n), n) * (e1 - R1.x) % n
alice_private_derived = (e1 - k1 * R1.x) % n
print("推导出的 Alice 的私钥：", alice_private_derived)

# 推导Bob的私钥
e2 = hashlib.sha256(message2.encode()).hexdigest()[:64]
e2 = int(e2, 16) % n
R2, s2 = bob_signature
k2 = mod_inv((s2 % n), n) * (e2 - R2.x) % n
bob_private_derived = (e2 - k2 * R2.x) % n
print("推导出的 Bob 的私钥：", bob_private_derived)