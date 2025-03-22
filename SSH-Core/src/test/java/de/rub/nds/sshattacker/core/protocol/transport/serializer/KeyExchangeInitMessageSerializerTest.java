/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyExchangeInitMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the KeyExchangeInitMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return KeyExchangeInitMessageParserTest.provideTestVectors();
    }

    /**
     * Test of KeyExchangeInitMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedCookie Bytes of the cookie
     * @param providedKeyExchangeAlgorithmsLength Length of the key exchange algorithm list
     * @param providedKeyExchangeAlgorithms Key exchange algorithm list
     * @param providedServerHostKeyAlgorithmsLength Length of the host key algorithm list
     * @param providedServerHostKeyAlgorithms Host key algorithm list
     * @param providedEncryptionAlgorithmsCToSLength Length of the encryption algorithm list (client
     *     to server)
     * @param providedEncryptionAlgorithmsCToS Encryption algorithm list (client to server)
     * @param providedEncryptionAlgorithmsSToCLength Length of the encryption algorithm list (server
     *     to client)
     * @param providedEncryptionAlgorithmsSToC Encryption algorithm list (server to client)
     * @param providedMacAlgorithmsCToSLength Length of the MAC algorithm list (client to server)
     * @param providedMacAlgorithmsCToS MAC algorithm list (client to server)
     * @param providedMacAlgorithmsSToCLength Length of the MAC algorithm list (server to client)
     * @param providedMacAlgorithmsSToC MAC algorithm list (server to client)
     * @param providedCompressionMethodsCToSLength Length of the compression algorithm list (client
     *     to server)
     * @param providedCompressionMethodsCToS Compression algorithm list (client to server)
     * @param providedCompressionMethodsSToCLength Length of the compression algorithm list (server
     *     to client)
     * @param providedCompressionMethodsSToC Compression algorithm list (server to client)
     * @param providedLanguagesCToSLength Length of the language list (client to server)
     * @param providedLanguagesCToS Language list (client to server)
     * @param providedLanguagesSToCLength Length of the language list (server to client)
     * @param providedLanguagesSToC Language list (server to client)
     * @param providedFirstKeyExchangePacketFollows Value of the firstKeyExchangePacketFollows field
     * @param providedReserved Value of the reserved field
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            byte[] providedCookie,
            int providedKeyExchangeAlgorithmsLength,
            String providedKeyExchangeAlgorithms,
            int providedServerHostKeyAlgorithmsLength,
            String providedServerHostKeyAlgorithms,
            int providedEncryptionAlgorithmsCToSLength,
            String providedEncryptionAlgorithmsCToS,
            int providedEncryptionAlgorithmsSToCLength,
            String providedEncryptionAlgorithmsSToC,
            int providedMacAlgorithmsCToSLength,
            String providedMacAlgorithmsCToS,
            int providedMacAlgorithmsSToCLength,
            String providedMacAlgorithmsSToC,
            int providedCompressionMethodsCToSLength,
            String providedCompressionMethodsCToS,
            int providedCompressionMethodsSToCLength,
            String providedCompressionMethodsSToC,
            int providedLanguagesCToSLength,
            String providedLanguagesCToS,
            int providedLanguagesSToCLength,
            String providedLanguagesSToC,
            byte providedFirstKeyExchangePacketFollows,
            int providedReserved) {
        KeyExchangeInitMessage msg = new KeyExchangeInitMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_KEXINIT);
        msg.setCookie(providedCookie);
        msg.setKeyExchangeAlgorithmsLength(providedKeyExchangeAlgorithmsLength);
        msg.setKeyExchangeAlgorithms(providedKeyExchangeAlgorithms);
        msg.setServerHostKeyAlgorithmsLength(providedServerHostKeyAlgorithmsLength);
        msg.setServerHostKeyAlgorithms(providedServerHostKeyAlgorithms);
        msg.setEncryptionAlgorithmsClientToServerLength(providedEncryptionAlgorithmsCToSLength);
        msg.setEncryptionAlgorithmsClientToServer(providedEncryptionAlgorithmsCToS);
        msg.setEncryptionAlgorithmsServerToClientLength(providedEncryptionAlgorithmsSToCLength);
        msg.setEncryptionAlgorithmsServerToClient(providedEncryptionAlgorithmsSToC);
        msg.setMacAlgorithmsClientToServerLength(providedMacAlgorithmsCToSLength);
        msg.setMacAlgorithmsClientToServer(providedMacAlgorithmsCToS);
        msg.setMacAlgorithmsServerToClientLength(providedMacAlgorithmsSToCLength);
        msg.setMacAlgorithmsServerToClient(providedMacAlgorithmsSToC);
        msg.setCompressionMethodsClientToServerLength(providedCompressionMethodsCToSLength);
        msg.setCompressionMethodsClientToServer(providedCompressionMethodsCToS);
        msg.setCompressionMethodsServerToClientLength(providedCompressionMethodsSToCLength);
        msg.setCompressionMethodsServerToClient(providedCompressionMethodsSToC);
        msg.setLanguagesClientToServerLength(providedLanguagesCToSLength);
        msg.setLanguagesClientToServer(providedLanguagesCToS);
        msg.setLanguagesServerToClientLength(providedLanguagesSToCLength);
        msg.setLanguagesServerToClient(providedLanguagesSToC);
        msg.setFirstKeyExchangePacketFollows(providedFirstKeyExchangePacketFollows);
        msg.setReserved(providedReserved);
        KeyExchangeInitMessageSerializer serializer = new KeyExchangeInitMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
