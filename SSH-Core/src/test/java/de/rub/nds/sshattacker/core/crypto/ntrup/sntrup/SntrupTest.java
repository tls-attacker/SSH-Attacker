/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;


public class SntrupTest {
    SntrupParameterSet set = SntrupParameterSet.KEM_SNTRUP_761;
    Sntrup sntrup = new Sntrup(set);

    @Test 
    public void testSntrup() {
        SntrupKeyPair kpair = sntrup.keyGen();
        sntrup.encaps(kpair.getPubK().getPubK());
        byte[] ciphertext = sntrup.getCyphertext();
        byte[] sharedSecret = sntrup.getSharedSecret();
        byte[] decodedSharedSecret = sntrup.decaps(kpair.getPrivK().getPrivK(), ciphertext);
        assertTrue("Encapsulated != Decapsulated", Arrays.equals(sharedSecret, decodedSharedSecret));
    }

}
