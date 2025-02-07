import random
from Crypto.Cipher import AES
import time
import matplotlib.pyplot as plt

class PublicParams:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

class AnamParams:
    def __init__(self, l, s, t):
        self.F = lambda pp, K, x, y: \
            int.from_bytes(AES.new(K, AES.MODE_ECB)
                           .encrypt(x.to_bytes(8, 'little')
                                    + y.to_bytes(8, 'little')), "little") % pp.p
        self.d = lambda ap, x: x % ap.t
        self.l = l
        self.s = s
        self.t = t

class KeyPair:
    def __init__(self, sk, pk):
        self.sk = sk
        self.pk = pk

class DoubleKey:
    def __init__(self, K, T, pk):
        self.K = K
        self.T = T
        self.pk = pk

def Gen(pp):
    sk = random.randint(0, pp.q - 1)
    pk = pow(pp.g, sk, pp.p)
    return KeyPair(sk, pk)

def Enc(pp, pk, msg):
    r = random.randint(0, pp.q - 1)
    c0 = (msg * pow(pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    return c0, c1

def Dec(pp, sk, c):
    return (c[0] * pow(c[1], -sk, pp.p)) % pp.p

def aGen(pp, ap, pk):
    K = random.randbytes(16)
    T = dict()
    for i in range(ap.l):
        T[pow(pp.g, i, pp.p)] = i
    return DoubleKey(K, T, pk)

def aEncCtr(pp, ap, dk, msg, cm, ctr):
    found = False
    for x in range(ctr[0], ap.s):
        for y in range(ctr[1], ap.t):
            t = ap.F(pp, dk.K, x, y)
            r = (cm + t) % pp.q
            if ap.d(ap, pow(pp.g, r, pp.p)) == y:
                found = True
                break
        if found:
            break
    ctr[1] = 0
    ctr[0] = (x + (1 if y == ap.t - 1 else 0)) % ap.s
    ctr[1] = (y + 1) % ap.t
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx, ctr

def aEnc(pp, ap, dk, msg, cm):
    while True:
        x = random.randint(0, ap.s - 1)
        y = random.randint(0, ap.t - 1)
        t = ap.F(pp, dk.K, x, y)
        r = (cm + t) % pp.q
        if ap.d(ap, pow(pp.g, r, pp.p)) == y:
            break
    c0 = (msg * pow(dk.pk, r, pp.p)) % pp.p
    c1 = pow(pp.g, r, pp.p)
    ctx = (c0, c1)
    return ctx

def aDec(pp, ap, dk, ctx):
    y = ap.d(ap, ctx[1])
    for x in range(ap.s):
        t = ap.F(pp, dk.K, x, y)
        s = (ctx[1] * pow(pp.g, -t, pp.p)) % pp.p
        if s in dk.T:
            return dk.T[s]
    return -1

# Settings
runs = 10
# Public Parameters (safe prime, pow(g, (p - 1) // 2, p) != 1)
p, g = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
FFFFFFFFFFFFFFFFAAAAAAAAAABBBBBBBBBBCCCCCCCCCC\
DDDDDDDDDDEEEEEEEEEEFFFFFFFFFFAAAAAAAAAABBBBBBBBBB\
CCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFAAAAAAAAAABBBBBBBBBB\
CCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFAAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFF", 0), 5 # Oakley group (RFC 2409)
# p, g = 1000000007, 5
q = p - 1
pp = PublicParams(p, q, g)
print("p =", pp.p)
print("q =", pp.q)
print("g =", pp.g)

# Anamorphic Parameters
l = 100000
s = 100
t = 100
ap = AnamParams(l, s, t)
print("l =", ap.l)
print("s =", ap.t)
print("t =", ap.s)

# Keys Generation
gen_start_time = time.time()
kp = Gen(pp)
dk = aGen(pp, ap, kp.pk)
gen_end_time = time.time()

print(f"Key generation time: {gen_end_time - gen_start_time:.10f} seconds")
print("(sk, pk) = (%d, %d)" % (kp.sk, kp.pk))
print("K =", dk.K)
print("T = [", ", ".join(str(a) + "->" + str(b) for (a, b) in
                         sorted([((pp.g ** i) % pp.p, i) for i in range(l)])), ']')

# Testing aEnc-> Dec and aEnc-> aDec
# msg = random.randint(1, pp.p - 1)
msg_text = "Glory to our Leader!"
msg = int.from_bytes(msg_text.encode(), 'big')
# cm = random.randint(0, l - 1)

# cm_text_arr = ["F", "*", "*", "k", "o", "u", "r", "L", "e", "a", "d", "e", "r", "!"]
# cm_text = cm_text_arr[random.randint(0, len(cm_text_arr) - 1)]
cm_text = "Fu"
cm = int.from_bytes(cm_text.encode(), 'big')
# ctr = [0, 0]

# ==================
# Execution time test for different input sizes
# input_sizes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
# input_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220]
# dec_times = [ 0 for i in range(len(input_sizes))]
# adec_times = [ 0 for i in range(len(input_sizes))]

# runs = 20
# for i in range(runs):
#     for j in range(len(input_sizes)):
    
#         msg_text = ""
#         for k in range(input_sizes[j]):
#             msg_text += chr(random.randrange(ord('A'), ord('z')))
#         msg = int.from_bytes(msg_text.encode(), 'big')

#         cm = random.randint(0, l - 1)

#         ctx = aEnc(pp, ap, dk, msg, cm)

#         start_time_Dec = time.time()
#         msg_ = Dec(pp, kp.sk, ctx)
#         end_time_Dec = time.time()

#         start_time_aDec = time.time()
#         cm_ = aDec(pp, ap, dk, ctx)
#         end_time_aDec = time.time()

#         execution_time_Dec = end_time_Dec - start_time_Dec
#         execution_time_aDec = end_time_aDec - start_time_aDec
#         #print("m1: %s, " % msg_text, "m2: %s, " % cm_text)

#         print("msg length: %d, " % len(msg_text), "cm: %d, " % cm)
#         print("msg_dec: %d, " % msg, "cm_dec: %d, " % cm)

#         ctx_hex = (hex(ctx[0]), hex(ctx[1]))

#         print("aEnc-> (c1, c2)")
#         print("c1 = ", ctx_hex[0])
#         print("c2 = ", ctx_hex[1])


#         msg_text_ = msg_.to_bytes((msg_.bit_length() + 7) // 8, 'big').decode()
#         #cm_text_ = cm_.to_bytes((cm_.bit_length() + 7) // 8, 'big').decode()

#         print("(c1, c2) -> Dec -> %s" % msg_text_, "(!)" if msg_ != -1 else "")
#         # print("(c1, c2) -> aDec -> %s" % cm_text_, "(!)" if cm_ != -1 else "")
#         print("(c1, c2) -> Dec -> %d" % cm_, "(!)" if cm_ != -1 else "")

#         print(f"Execution time: {execution_time_Dec:.10f} seconds for Dec")
#         print(f"Execution time: {execution_time_aDec:.10f} seconds for aDec")

#         dec_times[j] += execution_time_Dec
#         adec_times[j] += execution_time_aDec

#=======================================
# Execution time test for a single input size
for i in range(runs):    
    msg = int.from_bytes(msg_text.encode(), 'big')
    cm = int.from_bytes(cm_text.encode(), 'big')

    ctx = aEnc(pp, ap, dk, msg, cm)

    start_time_Dec = time.time()
    msg_ = Dec(pp, kp.sk, ctx)
    end_time_Dec = time.time()

    start_time_aDec = time.time()
    cm_ = aDec(pp, ap, dk, ctx)
    end_time_aDec = time.time()

    execution_time_Dec = end_time_Dec - start_time_Dec
    execution_time_aDec = end_time_aDec - start_time_aDec

    print("m1: %s, " % msg_text, "m2: %s, " % cm_text)
    print("msg length: %d, " % len(msg_text), "cm: %d, " % cm)
    print("msg_dec: %d, " % msg, "cm_dec: %d, " % cm)

    ctx_hex = (hex(ctx[0]), hex(ctx[1]))

    print("aEnc-> (c1, c2)")
    print("c1 = ", ctx_hex[0])
    print("c2 = ", ctx_hex[1])


    msg_text_ = msg_.to_bytes((msg_.bit_length() + 7) // 8, 'big').decode()
    cm_text_ = cm_.to_bytes((cm_.bit_length() + 7) // 8, 'big').decode()

    print("(c1, c2) -> Dec -> %s" % msg_text_, "(!)" if msg_ != -1 else "")
    print("(c1, c2) -> aDec -> %s" % cm_text_, "(!)" if cm_ != -1 else "")
    #print("(c1, c2) -> Dec -> %d" % cm_, "(!)" if cm_ != -1 else "")

    print(f"Execution time: {execution_time_Dec:.10f} seconds for Dec")
    print(f"Execution time: {execution_time_aDec:.10f} seconds for aDec")

# dec_times = [x / runs for x in dec_times]
# adec_times = [x / runs for x in adec_times]

# plt.plot(input_sizes, dec_times, label="Decryption")
# plt.plot(input_sizes, adec_times, label="Anamorphic Decryption")
# plt.xlabel("Input size")
# plt.ylabel("Execution time (s)")
# plt.title("Decryption vs Anamorphic Decryption")
# plt.legend()
# plt.show()


# Testing Enc-> Dec and Enc-> aDec
# for i in range(runs):
#     # m = random.randint(1, pp.p - 1)
#     m = msg
#     ctx = Enc(pp, kp.pk, m)
#     start_time_Dec = time.time()
#     msg_ = Dec(pp, kp.sk, ctx)
#     end_time_Dec = time.time()

#     start_time_aDec = time.time()
#     cm_ = aDec(pp, ap, dk, ctx)
#     end_time_aDec = time.time()

#     execution_time_Dec = end_time_Dec - start_time_Dec
#     execution_time_aDec = end_time_aDec - start_time_aDec

#     print("msg_text: %s, " % msg_text)
#     print("msg length: %d, " % len(msg_text))
#     print("msg_dec: %d, " % msg)

#     ctx_hex = (hex(ctx[0]), hex(ctx[1]))

#     print("msg -> Enc -> (c1, c2)")
#     print("c1 = ", ctx_hex[0])
#     print("c2 = ", ctx_hex[1])

#     msg_text_ = msg_.to_bytes((msg_.bit_length() + 7) // 8, 'big').decode()
#     if cm_ >= 0:
#         cm_text_ = cm_.to_bytes((cm_.bit_length() + 7) // 8, 'big').decode()
#     else:
#         cm_text_ = "Not found"

#     print("(c1, c2) -> Dec -> %d" % msg_, "(!)" if msg_ != -1 else "")
#     print("(c1, c2) -> aDec -> %s" % cm_text_, "(!)" if cm_ != -1 else "")

#     # print("%d-> Enc-> (%d, %d)-> Dec-> %d"
#     #       % (m, ctx[0], ctx[1], msg_))
#     # print("%d-> Enc-> (%d, %d)-> aDec-> %d"
#     #       % (m, ctx[0], ctx[1], cm_), "(!)" if cm_ != -1 else "")
    
#     print(f"Execution time: {execution_time_Dec:.10f} seconds for Dec")
#     print(f"Execution time: {execution_time_aDec:.10f} seconds for aDec")