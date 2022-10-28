/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class SntrupCoreTest {

    @Test
    public void testCore() {
        SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
        SntrupCore core = new SntrupCore(set);
        SntrupKeyPairCore keyPair = core.keyGenCore();
        Short r = Short.createRandomShort(set);
        Rounded c = core.encrypt(r, keyPair.getPubKey());
        Short rNew = core.decrypt(c, keyPair.getPrivKey());
        assertTrue("r != r'", r.equals(rNew));
    }
}
