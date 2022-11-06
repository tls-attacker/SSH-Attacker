/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;
import java.util.stream.LongStream;
import org.junit.Test;

public class R3Test {
    SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
    Random rand = new Random();

    @Test
    public void testIsInvertibleInR3() {
        // TODO: Find an invertible and not invertible R
    }

    @Test
    public void createR3() {

        long[] coeff = LongStream.range(0, set.getP()).map(l -> rand.nextInt(3) - 1).toArray();
        R3 r3 = new R3(set, coeff);
    }

    @Test
    public void testEncoding() {
        R3 r3;
        long[] coeff;
        for (int i = 0; i < 10; i++) {
            coeff = LongStream.range(0, set.getP()).map(l -> rand.nextInt(3) - 1).toArray();
            r3 = new R3(set, coeff);
            byte[] encoded = r3.encode();
            R3 r3N = R3.decode(set, encoded);
            assertTrue(r3.equals(r3N));
        }
    }
}
