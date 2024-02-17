/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import java.math.BigInteger;

/** M interval as mentioned in the Bleichenbacher paper. */
public class Interval {

    public BigInteger getLower() {
        return lower;
    }

    public void setLower(BigInteger lower) {
        this.lower = lower;
    }

    public BigInteger getUpper() {
        return upper;
    }

    public void setUpper(BigInteger upper) {
        this.upper = upper;
    }

    public BigInteger lower;
    public BigInteger upper;

    /**
     * @param a Start of interval
     * @param b End of interval
     */
    @SuppressWarnings("StandardVariableNames")
    public Interval(BigInteger a, BigInteger b) {
        super();
        lower = a;
        upper = b;
        if (a.compareTo(b) > 0) {
            throw new RuntimeException("something went wrong, a cannot be greater than b");
        }
    }
}
