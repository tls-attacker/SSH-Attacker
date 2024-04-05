/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;
import java.util.Random;
import java.util.stream.LongStream;
import org.junit.jupiter.api.Test;

public class R3Test {

    private final SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
    private final Random rand = new Random();

    @Test
    public void testIsInvertibleInR3() {
        R r = new R(set, LongStream.range(0, set.getP()).map(l -> rand.nextInt()).toArray());
        Optional<R3> r3Inv = R3.getInverseInR3(set, r);
        // Haven't found an R which is not invertible so far.
        for (int i = 0; i < 10; i++) {
            r3Inv = R3.getInverseInR3(set, r);
            if (r3Inv.isPresent()) {
                break;
            }
            r = new R(set, LongStream.range(0, set.getP()).map(l -> rand.nextInt()).toArray());
        }

        R3 r3 = new R3(set, r.stream().toArray());
        long[] res = new long[set.getP()];
        long[] def = new long[set.getP()];
        def[0] = -1;
        res[0] = 1;

        R3 expected = new R3(set, res);
        assertEquals(R3.multiply(r3, r3Inv.orElse(new R3(set, def))), expected);
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
            assertEquals(r3, r3N);
        }
    }
}
