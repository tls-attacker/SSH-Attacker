/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import java.math.BigInteger;

/**
 * An element of a galois field F_{2^m}.<br>
 * Please notice that every element in the field (and the reduction polynomial that defines the
 * field) is represented by a binary polynomial.<br>
 * These polynomials are represented by BigInteger bit-strings, where the i-th bit represents the
 * i-th coefficient.
 */
public class FieldElementF2m extends FieldElement {

    /**
     * Instantiates an element of a galois field F{2^m}.
     *
     * @param data The binary polynomial representing the element.<br>
     *     The degree must be smaller than the reduction polynomial's degree.
     * @param modulus The binary reduction polynomial defining the field.
     */
    public FieldElementF2m(BigInteger data, BigInteger modulus) {
        super(data, modulus);
    }

    public FieldElementF2m(FieldElementF2m other) {
        super(other);
    }

    @Override
    public FieldElementF2m createCopy() {
        return new FieldElementF2m(this);
    }

    @Override
    public FieldElement add(FieldElement element) {
        // Coefficients are added mod 2.
        BigInteger tmp = getData().xor(element.getData());
        return new FieldElementF2m(tmp, getModulus());
    }

    @Override
    public FieldElement mult(FieldElement element) {
        // Binary polynomial school book multiplication.

        BigInteger thisData = getData();
        BigInteger fieldData = element.getData();
        BigInteger tmp = BigInteger.ZERO;

        for (int i = 0; i < fieldData.bitLength(); i++) {
            if (fieldData.testBit(i)) {
                tmp = tmp.xor(thisData.shiftLeft(i));
            }
        }

        tmp = reduce(tmp);
        return new FieldElementF2m(tmp, getModulus());
    }

    @Override
    public FieldElement addInv() {
        /*
         * The characteristic of F_{2^m} is 2. Therefore, every element is its
         * own additive inverse. Like this.subtract(), this method is probably
         * never needed.
         */
        return this;
    }

    @Override
    public FieldElement multInv() {
        if (getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException(
                    "Element 0 does not have a multiplicative inverse in GF(2^m)");
        }

        if (getData().equals(BigInteger.ONE)) {
            return this;
        }

        // Polynomial EEA:
        BigInteger r2 = getModulus();
        BigInteger r1 = getData();
        BigInteger t2 = BigInteger.ZERO;
        BigInteger t1 = BigInteger.ONE;

        do {
            BigInteger[] division = polynomialDivision(r2, r1);
            // r = r2 mod r1
            BigInteger r = division[1];
            // q = (r2 - r) / r1
            BigInteger q = division[0];

            // t = t2 - (t1 * q)
            FieldElementF2m pointT1Polynomial = new FieldElementF2m(t1, getModulus());
            FieldElementF2m pointQPolynomial = new FieldElementF2m(q, getModulus());

            BigInteger t = pointT1Polynomial.mult(pointQPolynomial).getData();
            t = reduce(t);
            t = t2.xor(t);

            t2 = t1;
            t1 = t;
            r2 = r1;
            r1 = r;

        } while (!r1.equals(BigInteger.ONE) && !r1.equals(BigInteger.ZERO));

        // t1 * this.getData() == 1
        return new FieldElementF2m(t1, getModulus());
    }

    /**
     * Polynomial division f/p.<br>
     * Returns an BigInteger array representing the polynomials q and r with: <br>
     * q * p + r = f.
     *
     * @param f A BigInteger representing a binary polynomial.
     * @param p A BigInteger representing a binary polynomial.
     */
    private static BigInteger[] polynomialDivision(
            @SuppressWarnings("StandardVariableNames") BigInteger f, BigInteger p) {
        int modLength = p.bitLength();
        BigInteger q = BigInteger.ZERO;
        while (f.bitLength() >= modLength && modLength != 0) {
            BigInteger tmp = BigInteger.ONE;
            tmp = tmp.shiftLeft(f.bitLength() - modLength);
            q = q.xor(tmp);

            BigInteger shift = p.multiply(tmp);
            f = f.xor(shift);
        }
        // q is the quotient.
        // f is the remainder.
        return new BigInteger[] {q, f};
    }

    /**
     * Returns polynomial mod this.getModulus().
     *
     * @param polynomial A BigInteger representing a binary polynomial.
     */
    private BigInteger reduce(BigInteger polynomial) {
        return polynomialDivision(polynomial, getModulus())[1];
    }

    /**
     * Computes the square of this and then potentiate the result with exponent. The result is
     * (this^2)^exponent.
     *
     * @param exponent An Integer representing the exponent.
     * @return The resulting field element of (this^2)^exponent
     */
    public FieldElementF2m squarePow(int exponent) {
        FieldElement square = mult(this);
        for (int i = 1; i < exponent; i++) {
            square = square.mult(square);
        }
        return (FieldElementF2m) square;
    }
}
