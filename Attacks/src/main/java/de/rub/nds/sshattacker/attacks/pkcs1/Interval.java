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

    public BigInteger lower;
    public BigInteger upper;

    /**
     * @param a Start of interval
     * @param b End of interval
     */
    public Interval(BigInteger a, BigInteger b) {
        this.lower = a;
        this.upper = b;
        if (a.compareTo(b) > 0) {
            throw new RuntimeException("something went wrong, a cannot be greater than b");
        }
    }
}
