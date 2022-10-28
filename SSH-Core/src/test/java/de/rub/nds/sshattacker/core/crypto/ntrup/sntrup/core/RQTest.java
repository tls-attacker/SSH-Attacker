/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.assertTrue;

import java.util.Random;
import java.util.stream.LongStream;

import org.junit.Test;

public class RQTest {
    SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;

    @Test
    public void testRQcreation() {

        long[] coeff = new long[set.getP()];
        coeff[0] = -1888;
        RQ rq = new RQ(set, coeff);
        assertTrue("Coefficients have to be between (-(q-1)/2 and (q-1)/2", rq.stream().toArray()[0] == -1888);
    }

    @Test
    public void testInvert() {
        long[] coeff = new long[set.getP()];
        coeff[0] = -1888;
        RQ rq = new RQ(set, coeff);
        RQ rqInv = RQ.invert(rq);

        long[] res = new long[set.getP()];
        res[0] = 1;
        RQ rqRes = new RQ(set, res);
        assertTrue("rqInv is not the inversion of", RQ.multiply(rq, rqInv).equals(rqRes));
    }

    @Test
    public void testEncoding() {
        Random rand = new Random();
        long[] coefficient;
        for (int i = 0; i < 100; i++) {
            coefficient = LongStream.range(0, set.getP())
                    .map(l -> rand.nextInt(set.getQ()) % set.getQ() - ((set.getQ() + 1) / 2)).toArray();
            RQ rq = new RQ(set, coefficient);
            byte[] encoded = rq.encode();
            RQ decoded = RQ.decode(set, encoded);
            assertTrue("rq != decoded", rq.equals(decoded));
        }

    }
}
