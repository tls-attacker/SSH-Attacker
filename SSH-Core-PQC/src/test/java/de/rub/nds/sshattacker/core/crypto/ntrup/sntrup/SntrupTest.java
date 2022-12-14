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

import de.rub.nds.sshattacker.core.crypto.kex.CustomSntrup;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;


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
        CustomSntrup sntrupClient = new CustomSntrup(set, round1);
        CustomSntrup sntrupServer = new CustomSntrup(set, round1);

        sntrupClient.generateLocalKeyPair();
        assertFalse("Key Generation not successfull", sntrupClient.getLocalKeyPair() == null);
        assertFalse("Private Key is null", sntrupClient.getLocalKeyPair().getPrivate() == null);
        assertFalse("Public Key is null", sntrupClient.getLocalKeyPair().getPublic() == null);

        sntrupServer.setRemotePublicKey(sntrupClient.getLocalKeyPair().getPublic().getEncoded());
        byte[] ciphertext = sntrupServer.encryptSharedSecret();
        assertFalse("could not encrypt shared Secret", sntrupServer.getSharedSecret() == null);
        assertFalse("could not encrypt shared Secret", sntrupServer.getEncryptedSharedSecret() == null);
        assertTrue("could not encrypt shared Secret", Arrays.equals(sntrupServer.getEncryptedSharedSecret(), ciphertext));

        sntrupClient.setEncryptedSharedSecret(ciphertext);

        try {
            sntrupClient.decryptSharedSecret();
            assertFalse(sntrupClient.getSharedSecret() == null);
            assertTrue(sntrupClient.getSharedSecret().equals(sntrupServer.getSharedSecret()));
            assertTrue(Arrays.equals(sntrupClient.getEncryptedSharedSecret(),sntrupServer.getEncryptedSharedSecret()));

        } catch (Exception e) {
            assertTrue("This should not happen: " + e, false);
        }

    }
}
