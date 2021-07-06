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

public class EllipticCurveSECT163R1 extends EllipticCurveOverF2m {

    public EllipticCurveSECT163R1() {
        super(new BigInteger("07B6882CAAEFA84F9554FF8428BD88E246D2782AE2", 16), new BigInteger(
                "0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9", 16), new BigInteger(
                "800000000000000000000000000000000000000c9", 16), new BigInteger(
                "0369979697AB43897789566789567F787A7876A654", 16), new BigInteger(
                "00435EDB42EFAFB2989D51FEFCE3C80988F41FF883", 16), new BigInteger(
                "03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B", 16));
    }
}
