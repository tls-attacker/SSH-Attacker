/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.sshattacker.core.constants.PQKemNames;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class SntrupTest {

    public static Stream<Arguments> provideTestVectors() {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();

        argumentsBuilder.add(Arguments.of(PQKemNames.SNTRUP4591761));
        argumentsBuilder.add(Arguments.of(PQKemNames.SNTRUP761));
        return argumentsBuilder.build();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSntrup(PQKemNames kemName) throws CryptoException {
        Sntrup sntrupClient = new Sntrup(kemName);
        Sntrup sntrupServer = new Sntrup(kemName);

        sntrupClient.generateLocalKeyPair();
        assertNotNull(sntrupClient.getLocalKeyPair());
        assertNotNull(sntrupClient.getLocalKeyPair().getPrivate());
        assertNotNull(sntrupClient.getLocalKeyPair().getPublic());

        sntrupServer.setRemotePublicKey(sntrupClient.getLocalKeyPair().getPublic().getEncoded());
        byte[] ciphertext = sntrupServer.encryptSharedSecret();
        assertNotNull(sntrupServer.getSharedSecret());
        assertNotNull(sntrupServer.getEncryptedSharedSecret());
        assertEquals(ciphertext, sntrupServer.getEncryptedSharedSecret());

        sntrupClient.setEncryptedSharedSecret(ciphertext);

        sntrupClient.decryptSharedSecret();
        assertNotNull(sntrupClient.getSharedSecret());
        assertArrayEquals(sntrupClient.getSharedSecret(), sntrupServer.getSharedSecret());
        assertArrayEquals(
                sntrupClient.getEncryptedSharedSecret(), sntrupServer.getEncryptedSharedSecret());
    }
}
