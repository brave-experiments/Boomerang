"""

This sage script was used to produce generators for the curve parameters.

NOTE: This script was only actually used for T384. The numbers for T256 were taken from ZKAttest's implementation. 

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

print("T256 (%d, %d)" % make_generator(0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117, 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, -3, 0xb441071b12f4a0366fb552f8e21ed4ac36b06aceeb354224863e60f20219fc56))
print("T384 (%d, %d)" % make_generator(0xfffffffffffffffffffffffffffffffffffffffffffffffeaf5f689f8669fb41b08d5f5edffd26599c434bbd978917c5, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, 0x821dfdc940e7f074ac481f8b2870c48962cce56abd72dfc42813a944cea15df78dc0a2d97fbf031ed26c9076826940ba, 0x9b5b584b655fdcb087d37f8c4fee893c0499223db5e004c674ea0dee48a4ec0c9e9f684099f2a51c62a2cce400cb1e4b))
