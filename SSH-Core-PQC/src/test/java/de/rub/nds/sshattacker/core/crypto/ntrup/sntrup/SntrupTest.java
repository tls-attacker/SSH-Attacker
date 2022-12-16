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

import de.rub.nds.sshattacker.core.constants.OpenQuantumSafeKemNames;
import de.rub.nds.sshattacker.core.crypto.kex.CustomSntrup;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class SntrupTest {

    public static Stream<Arguments> provideTestVectors() {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();

        argumentsBuilder.add(Arguments.of(OpenQuantumSafeKemNames.SNTRUP4591761));
        argumentsBuilder.add(Arguments.of(OpenQuantumSafeKemNames.SNTRUP761));
        return argumentsBuilder.build();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSntrup(OpenQuantumSafeKemNames kemName) {
        CustomSntrup sntrupClient = new CustomSntrup(kemName);
        CustomSntrup sntrupServer = new CustomSntrup(kemName);

        sntrupClient.generateLocalKeyPair();
        assertFalse("Key Generation not successfull", sntrupClient.getLocalKeyPair() == null);
        assertFalse("Private Key is null", sntrupClient.getLocalKeyPair().getPrivate() == null);
        assertFalse("Public Key is null", sntrupClient.getLocalKeyPair().getPublic() == null);

        sntrupServer.setRemotePublicKey(sntrupClient.getLocalKeyPair().getPublic().getEncoded());
        byte[] ciphertext = sntrupServer.encryptSharedSecret();
        assertFalse("could not encrypt shared Secret", sntrupServer.getSharedSecret() == null);
        assertFalse(
                "could not encrypt shared Secret", sntrupServer.getEncryptedSharedSecret() == null);
        assertTrue(
                "could not encrypt shared Secret",
                Arrays.equals(sntrupServer.getEncryptedSharedSecret(), ciphertext));

        sntrupClient.setEncryptedSharedSecret(ciphertext);

        try {
            sntrupClient.decryptSharedSecret();
            assertFalse(sntrupClient.getSharedSecret() == null);
            assertTrue(sntrupClient.getSharedSecret().equals(sntrupServer.getSharedSecret()));
            assertTrue(
                    Arrays.equals(
                            sntrupClient.getEncryptedSharedSecret(),
                            sntrupServer.getEncryptedSharedSecret()));

        } catch (Exception e) {
            assertTrue("This should not happen: " + e, false);
        }
    }
}
