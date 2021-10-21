/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import java.math.BigInteger;

public class EllipticCurveSECT163R2 extends EllipticCurveOverF2m {
    public EllipticCurveSECT163R2() {
        super(
                BigInteger.ONE,
                new BigInteger("020A601907B8C953CA1481EB10512F78744A3205FD", 16),
                new BigInteger("800000000000000000000000000000000000000c9", 16),
                new BigInteger("03F0EBA16286A2D57EA0991168D4994637E8343E36", 16),
                new BigInteger("00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1", 16),
                new BigInteger("040000000000000000000292FE77E70C12A4234C33", 16),
                BigInteger.valueOf(2));
    }
}
