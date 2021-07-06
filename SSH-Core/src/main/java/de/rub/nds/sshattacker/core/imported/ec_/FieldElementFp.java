/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.imported.ec_;

import java.math.BigInteger;

/**
 * An element of the field F_p (with p being a prime number).
 */
public class FieldElementFp extends FieldElement {

    /**
     * Instantiates the element data in the field F_modulus. With modulus being
     * a prime number.
     */
    public FieldElementFp(BigInteger data, BigInteger modulus) {
        super(data.mod(modulus), modulus);
    }

    @Override
    public FieldElement add(FieldElement f) {
        BigInteger tmp = this.getData().add(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement mult(FieldElement f) {
        BigInteger tmp = this.getData().multiply(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement addInv() {
        BigInteger tmp = this.getData().negate();
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement multInv() {
        if (this.getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException();
        }
        BigInteger tmp = this.getData().modInverse(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }
}
