"""

This sage script was used to produce generators for the curve parameters.

"""

from sage import *

def make_generator(r, q, a4, a6):
    """
    generate_params. This function returns the generator of the curve over `q` of order `r` specified
    by the short Weierstrass equation y^3 = x^3 + a4x + a6. We then ask Sage to produce a generator

    :param r: the order of the underlying scalar field.
    :param q: the order of the elliptic curve.
    :param a4: the coefficient of x in the short Weierstrass equation.
    :param a6: the constant term in the short Weierstrass equation.
    :return a generator for the curve.
    """

    # Use Fr as the scalar field.
    Fr = GF(r)

    # Now set up a4 and a6.
    a4 = Fr(a4)
    a6 = Fr(a6)

    # And the curve. Setting the order is probably overkill, but better to be safe.
    E = EllipticCurve(Fr, (a4, a6))
    E.set_order(q)
    return E.gens()[0][0], E.gens()[0][1]

print("Tsecq256k1 (%d, %d)" % make_generator(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7))
