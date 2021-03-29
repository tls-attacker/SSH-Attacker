/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.imported.ec_;

import java.math.BigInteger;

public class EllipticCurveSECT283K1 extends EllipticCurveOverF2m {

    public EllipticCurveSECT283K1() {
        super(BigInteger.ZERO, BigInteger.ONE, new BigInteger(
                "800000000000000000000000000000000000000000000000000000000000000000010a1", 16), new BigInteger(
                "0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836", 16), new BigInteger(
                "01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259", 16), new BigInteger(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61", 16));
    }
}
