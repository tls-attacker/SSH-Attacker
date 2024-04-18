/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import java.math.BigInteger;

/** An abstract class that provides functionality for elliptic curve over galois fields. */
public abstract class EllipticCurve {

    private Point basePoint;
    private BigInteger basePointOrder;
    private BigInteger cofactor;

    /** The modulus of the field over which the curve is defined. */
    private final BigInteger modulus;

    /**
     * Every child class must define its own public constructor. These constructors must be able to
     * set the coefficients for the curve. They can use this constructor to set the value of
     * modulus.
     *
     * @param modulus The modulus of the field over which the curve is defined.
     */
    protected EllipticCurve(BigInteger modulus) {
        super();
        this.modulus = modulus;
    }

    /**
     * Every child class must define its own public constructor. These constructors must be able to
     * set the coefficients for the curve. They can use this constructor to set the values of
     * modulus, basePoint and basePointOrder.
     *
     * @param modulus The modulus of the field over which the curve is defined.
     * @param basePointX The x coordinate of the base point.
     * @param basePointY The y coordinate of the base point.
     * @param basePointOrder The order of the base point.
     * @param cofactor The cofactor of the curve.
     */
    protected EllipticCurve(
            BigInteger modulus,
            BigInteger basePointX,
            BigInteger basePointY,
            BigInteger basePointOrder,
            BigInteger cofactor) {
        super();
        this.modulus = modulus;
        basePoint = getPoint(basePointX, basePointY);
        this.basePointOrder = basePointOrder;
        this.cofactor = cofactor;
    }

    /**
     * Returns the result of p + q on this curve. If one point is null, the result will be null. If
     * one point is not on the curve and the calculations would require dividing by 0, the result
     * will be the point at infinity.
     *
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @param q A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The resulting point r = p + q.
     */
    public Point add(Point p, Point q) {
        if (p.isAtInfinity()) {
            // O + q == q
            return q;
        }

        if (q.isAtInfinity()) {
            // p + O == p
            return p;
        }

        if (inverse(p).equals(q)) {
            // p == -q <=> -p == q
            // => p + q = O
            return new Point();
        }

        return additionFormular(p, q);
    }

    /**
     * Returns k*p on this curve. If the point is not on the curve and the calculations would
     * require dividing by 0, the result will be the point at infinity.
     *
     * @param k A scalar which is multiplied with p.
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The resulting point r = k * p.
     */
    public Point mult(@SuppressWarnings("StandardVariableNames") BigInteger k, Point p) {
        if (k.compareTo(BigInteger.ZERO) < 0) {
            k = k.negate();
            p = inverse(p);
        }

        // Double-and-add
        Point q = getPoint(BigInteger.ZERO, BigInteger.ZERO); // q == O

        for (int i = k.bitLength(); i > 0; i--) {

            q = add(q, q);

            if (k.testBit(i - 1)) {
                q = add(q, p);
            }
        }

        return q;
    }

    /**
     * Returns the unique point q with the property p + q = O on this curve. If p is null the result
     * will be null.
     *
     * @param p A point whose coordinates are elements of the field over which the curve is defined
     *     or the point at infinity.
     * @return The inverse point of this. this + (-this) = 0 where 0 is the point at infinity.
     */
    public Point inverse(Point p) {
        if (p.isAtInfinity()) {
            // -O == O
            return p;
        } else {
            return inverseAffine(p);
        }
    }

    /**
     * Returns an affine point with coordinates x and y. The point's coordinates are elements of the
     * field over which this curve is defined. Whenever possible, this method should be used instead
     * of creating a point via its own constructor.
     *
     * @param x The x coordinate of the point.
     * @param y The y coordinate of the point.
     * @return Returns an affine point with coordinates x and y.
     */
    public abstract Point getPoint(BigInteger x, BigInteger y);

    /**
     * Checks whether a point is on the curve.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined or the point at infinity.
     * @return True iff p is a point on the curve.
     */
    public abstract boolean isOnCurve(Point p);

    /**
     * Computes the unique (affine) point given point p on this curve.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined.
     * @return The unique (affine) point q on this curve with p + q = 0 where 0 is the point at
     *     infinity.
     */
    protected abstract Point inverseAffine(Point p);

    /**
     * Returns p+q for two affine points p and q, with p != -q. If one point is not on the curve and
     * the calculations would require dividing by 0, the result will be the point at infinity.
     *
     * @param p An affine point whose coordinates are elements of the field over which the curve is
     *     defined.
     * @param q An affine point whose coordinates are elements of the field over which the curve is
     *     defined. Must not be equal to -p.
     * @return The point p + q for two affine points p + q with p != -q.
     */
    protected abstract Point additionFormular(Point p, Point q);

    public Point getBasePoint() {
        return basePoint;
    }

    public BigInteger getBasePointOrder() {
        return basePointOrder;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getCofactor() {
        return cofactor;
    }

    public abstract Point createAPointOnCurve(BigInteger x);

    public abstract FieldElement createFieldElement(BigInteger value);
}
