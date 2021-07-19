/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import java.math.BigInteger;

public class EllipticCurveSECP160R1 extends EllipticCurveOverFp {
    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveSECP160R1() {
        super(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16), new BigInteger(
                "1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16), new BigInteger(
                "ffffffffffffffffffffffffffffffff7fffffff", 16), new BigInteger(
                "4a96b5688ef573284664698968c38bb913cbfc82", 16), new BigInteger(
                "23a628553168947d59dcc912042351377ac5fb32", 16), new BigInteger(
                "0100000000000000000001f4c8f927aed3ca752257", 16), BigInteger.ONE);
    }
}
