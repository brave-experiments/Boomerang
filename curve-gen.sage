# Implementation of Broker's algorithm https://arxiv.org/pdf/0712.2022.pdf
# Code modified from https://pastebin.com/K0uA8qPB found in https://crypto.stackexchange.com/questions/89899/finding-an-elliptic-curve-of-specific-order
# Input: A prime N
# Output: A field F_t, and an elliptic curve E such that the order of E(F_t) is N.
from itertools import combinations
from timeit import default_timer as timer

# The characteristic of the base fields for each curve. E.g if E if a curve over F_p, then the value below is p.

# This is the 256-bit NIST Koblitz curve.
SECP256K1_FIELD_CHARACTERISTIC = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

# This is also known as P-256
SECP256R1_FIELD_CHARACTERISTIC = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

# This is also known as P-384
SECP384R1_FIELD_CHARACTERISTIC = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff

# This is also known as P-521
SECP521R1_FIELD_CHARACTERISTIC = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff


def cornacchia(d, m):
	Q = gp.Qfb(1,0,d)
	sol = list(Q.qfbsolve(m))
	if len(sol) == 0:
		return None
	return [ZZ(sol[0]), ZZ(sol[1])]

def find_curve_of_order(n):
	r = 0
	logn = int(log(n,2).n())
	while True:
		S = [ legendre_symbol(-1, p)*p for p in prime_range(max(3,r*logn), (r+1)*logn) if legendre_symbol(n, p) == 1]
		for i in range(1, len(S)):
			for L in combinations(S, i):
				D = prod(L)
				if D % 8 != 5 or D >= (r*logn)^2:
					continue
				solution = cornacchia(-D, 4*n)
				if solution == None:
					continue
				x = solution[0]
				if is_prime(n+1+x):
					p = n+1+x
				elif is_prime(n+1-x):
					p = n+1-x
				else:
					continue
				P = hilbert_class_polynomial(D)
				roots = P.roots(ring=GF(p))
				if len(roots) > 0:
					E = EllipticCurve_from_j(roots[0][0]).change_ring(GF(p))
					if E.order() == n:
						return E
					else:
						return E.quadratic_twist()
		r += 1



def find_order(characteristic: int):
    """
    find_order. Helper function for finding a curve of order `characteristic`.

    :param characteristic: the desired order of the curve that is found.
    :return the time taken (in seconds) to find the curve.
    """
    print("Finding order: ")

    start = timer()
    E = find_curve_of_order(characteristic)
    end = timer()
    if E.order() == characteristic:
        print(E)
        print("Discriminant: %x" % E.discriminant())
        print("J invariant: %x" % E.j_invariant())
    else:
        print("Error: could not find curve of characteristic %d" % characteristic)

    return end - start


def main():
    """
    main. Finds a correctly ordered curve for each listed field characteristic and prints out the time taken (in seconds)
    for each search.
    """
    k256_time = find_order(SECP256K1_FIELD_CHARACTERISTIC)
    p256_time = find_order(SECP256R1_FIELD_CHARACTERISTIC)
    p384_time = find_order(SECP384R1_FIELD_CHARACTERISTIC)
    p521_time = find_order(SECP521R1_FIELD_CHARACTERISTIC)

    print("Time for K256(s): %f, P256(s): %f, P384(s): %f, P521(s): %f" % (k256_time, p256_time, p384_time, p521_time))

if __name__ == "__main__":
    main()

