/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Random;
import java.util.stream.LongStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

public class RQTest {
    private static final Logger LOGGER = LogManager.getLogger();
    SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
    Random rand = new Random();
    long[] coefficient;

    @Test
    public void testRQcreation() {

        long[] coeff = new long[set.getP()];
        coeff[0] = -1888;
        RQ rq = new RQ(set, coeff);
        assertEquals(rq.stream().toArray()[0], -1888);
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
        assertEquals(RQ.multiply(rq, rqInv), rqRes);
    }

    @Test
    public void testEncoding() {

        for (int i = 0; i < 100; i++) {
            coefficient =
                    LongStream.range(0, set.getP())
                            .map(
                                    l ->
                                            rand.nextInt(set.getQ()) % set.getQ()
                                                    - ((set.getQ() + 1) / 2))
                            .toArray();
            RQ rq = new RQ(set, coefficient);
            byte[] encRq = rq.encode();
            RQ rqNew = RQ.decode(set, encRq);
            assertEquals(rq, rqNew);
        }
    }

    @Test
    public void testEncodingOld() {
        coefficient =
                LongStream.range(0, set.getP())
                        .map(l -> rand.nextInt(set.getQ()) - ((set.getQ() + 1) / 2))
                        .toArray();
        RQ rq = new RQ(set, coefficient);
        byte[] encRq = rq.encode_old();
        RQ rqNew = RQ.decode_old(set, encRq);
        assertEquals(rq, rqNew);
    }
}
