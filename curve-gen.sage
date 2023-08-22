# Implementation of Broker's algorithm https://arxiv.org/pdf/0712.2022.pdf
# Code modified from https://pastebin.com/K0uA8qPB found in https://crypto.stackexchange.com/questions/89899/finding-an-elliptic-curve-of-specific-order
# Input: A prime N
# Output: A field F_t, and an elliptic curve E such that the order of E(F_t) is N.
from itertools import combinations

SECP256K1_CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def cornacchia(d, m):
	Q = gp.Qfb(1,0,d)
	sol = list(Q.qfbsolve(m))
	if len(sol) == 0:
		return None
	return [ZZ(sol[0]), ZZ(sol[1])]

def find_curve_of_order(n):
	r = 0
	logn = int(log(n))
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
		
E = find_curve_of_order(SECP256K1_CURVE_ORDER)
if E.order() == SECP256K1_CURVE_ORDER:
	print(E)