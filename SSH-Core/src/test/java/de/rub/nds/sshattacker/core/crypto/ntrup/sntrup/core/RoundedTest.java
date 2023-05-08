/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.Test;

import java.util.Random;
import java.util.stream.LongStream;

public class RoundedTest {

    final Random rand = new Random();
    long[] coefficient;
    final SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;

    @Test
    public void roundTest() {
        for (int i = 0; i < 10; i++) {
            coefficient =
                    LongStream.range(0, set.getP())
                            .map(l -> rand.nextInt(set.getQ()) - ((set.getQ() + 1) / 2))
                            .toArray();
            RQ rq = new RQ(set, coefficient);
            Rounded rounded = Rounded.round(rq);
            assertTrue(Rounded.is_rounded(set, rounded.stream().toArray()));
        }
    }

    @Test
    public void testEncoding() {
        coefficient =
                LongStream.range(0, set.getP())
                        .map(l -> rand.nextInt(set.getQ()) - ((set.getQ() + 1) / 2))
                        .toArray();
        Rounded r = Rounded.round(new RQ(set, coefficient));
        byte[] encR = r.encode();
        Rounded rNew = Rounded.decode(set, encR);
        assertEquals(r, rNew);
    }

    @Test
    public void testEncodingOld() {
        coefficient =
                LongStream.range(0, set.getP())
                        .map(l -> rand.nextInt(set.getQ()) - ((set.getQ() + 1) / 2))
                        .toArray();

        Rounded r = Rounded.round(new RQ(set, coefficient));
        byte[] encR = r.encode_old();
        Rounded rNew = Rounded.decode_old(set, encR);
        assertEquals(r, rNew);
    }
}
