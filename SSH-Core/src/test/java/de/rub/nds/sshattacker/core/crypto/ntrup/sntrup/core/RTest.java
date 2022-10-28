/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import java.util.Random;
import java.util.stream.IntStream;
import org.junit.Test;

public class RTest {
    SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
    Random rand = new Random();

    @Test
    public void randomSmallTest(){
        R r;
        for (int i : IntStream.range(0,10).toArray()){
            r = R.randomSmall(set);
            assert(!r.stream().filter(l -> Math.abs(l)>1).findFirst().isPresent());
        }
    }
}
