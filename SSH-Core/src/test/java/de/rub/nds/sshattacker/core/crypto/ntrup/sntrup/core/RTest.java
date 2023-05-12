/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.Test;

public class RTest {
    private final SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;

    @Test
    public void randomSmallTest() {
        R r;
        for (int i = 0; i < 10; i++) {
            r = R.randomSmall(set);
            assertFalse(r.stream().filter(l -> Math.abs(l) > 1).findFirst().isPresent());
        }
    }
}
