/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import java.math.BigInteger;

/** An element of the field F_p (with p being a prime number). */
public class FieldElementFp extends FieldElement {

    /**
     * Instantiates the element data in the field F_modulus.
     *
     * @param data the element in the field F_modulus
     * @param modulus the field modulus. The modulus must be prime.
     */
    public FieldElementFp(BigInteger data, BigInteger modulus) {
        super(data.mod(modulus), modulus);
    }

    @SuppressWarnings("unused")
    private FieldElementFp() {
        super(null, null);
    }

    @Override
    public FieldElement add(FieldElement element) {
        BigInteger tmp = getData().add(element.getData());
        tmp = tmp.mod(getModulus());
        return new FieldElementFp(tmp, getModulus());
    }

    @Override
    public FieldElement mult(FieldElement element) {
        BigInteger tmp = getData().multiply(element.getData());
        tmp = tmp.mod(getModulus());
        return new FieldElementFp(tmp, getModulus());
    }

    @Override
    public FieldElement addInv() {
        BigInteger tmp = getData().negate();
        tmp = tmp.mod(getModulus());
        return new FieldElementFp(tmp, getModulus());
    }

    @Override
    public FieldElement multInv() {
        if (getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException(
                    "Element 0 does not have a multiplicative inverse in GF(p)");
        }
        BigInteger tmp = getData().modInverse(getModulus());
        return new FieldElementFp(tmp, getModulus());
    }
}
