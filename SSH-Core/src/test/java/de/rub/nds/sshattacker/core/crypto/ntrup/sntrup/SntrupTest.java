/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.sshattacker.core.crypto.keys.CustomHybridPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import cc.redberry.rings.bigint.BigInteger;

public class SntrupTest {

    public static Stream<Arguments> provideTestVectors() {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();

        argumentsBuilder.add(Arguments.of(SntrupParameterSet.KEM_SNTRUP_761, false));
        argumentsBuilder.add(Arguments.of(SntrupParameterSet.KEM_SNTRUP_761, true));
        return argumentsBuilder.build();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSntrup(SntrupParameterSet set, boolean round1) {
        Sntrup sntrupClient = new Sntrup(set, round1);
        Sntrup sntrupServer = new Sntrup(set, round1);

        sntrupClient.generateLocalKeyPair();
        assertFalse("Key Generation not successfull", sntrupClient.getLocalKeyPair() == null);
        assertFalse("Key Generation not successfull", sntrupClient.getLocalKeyPair().getPrivate() == null);
        assertFalse("Key Generation not successfull", sntrupClient.getLocalKeyPair().getPublic() == null);

        sntrupServer.setRemotePublicKey(sntrupClient.getLocalKeyPair().getPublic().getEncoded());
        byte[] ciphertext = sntrupServer.encryptSharedSecret();
        assertFalse("could not encrypt shared Secret", sntrupServer.getSharedSecret() == null);
        assertFalse("could not encrypt shared Secret", sntrupServer.getEncryptedSharedSecret() == null);
        assertTrue("could not encrypt shared Secret", sntrupServer.getEncryptedSharedSecret() == ciphertext);

        sntrupClient.setEncryptedSharedSecret(ciphertext);

        try {
            sntrupClient.decryptSharedSecret();
            assertFalse("Could not decrypt shared Secret", sntrupClient.getSharedSecret() == null);
            assertTrue("Could not decrypt shared Secret",
                    sntrupClient.getSharedSecret() == sntrupServer.getSharedSecret());
            assertTrue("Could not decrypt shared Secret",
                    sntrupClient.getSharedSecret() == sntrupServer.getSharedSecret());

        } catch (Exception e) {
            assertTrue("This should not happen: " + e, false);
        }

    }
}
