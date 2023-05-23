/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ExtensionInfoMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ExtensionInfoMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ExtensionInfoMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ExtensionInfoMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ExtensionInfoMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedExtensionCount Count of the extensions
     * @param providedNameLengthOfServerSigAlgsExtension Length of the 'server-sig-algs' string: 15
     * @param providedNameOfServerSigAlgsExtension The String 'server-sig-algs'
     * @param providedValueLengthOfServerSigAlgsExtension Length of the value of the server-sig-algs
     *     extension
     * @param providedValueOfServerSigAlgsExtension Value of server-sig-algs extension(accepted
     *     public key algorithms)
     * @param providedNameLengthOfDelayCompressionExtension Length of the 'delay-compression'
     *     string: 17
     * @param providedNameOfDelayCompressionExtension The String 'delay-compression'
     * @param providedValueLengthOfDelayCompressionExtension Value of delay-compression extension
     *     (CompressionMethodsCtoS, CompressionMethodsStoC)
     * @param providedCompressionMethodsClientToServerLength Length of compression methods client to
     *     server
     * @param providedCompressionMethodsClientToServer Compression methods client to server
     * @param providedCompressionMethodsServerToClientLength Length of compression methods server to
     *     client
     * @param providedCompressionMethodsServerToClient Compression methods server to client
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedExtensionCount,
            int providedNameLengthOfServerSigAlgsExtension,
            String providedNameOfServerSigAlgsExtension,
            int providedValueLengthOfServerSigAlgsExtension,
            String providedValueOfServerSigAlgsExtension,
            int providedNameLengthOfDelayCompressionExtension,
            String providedNameOfDelayCompressionExtension,
            int providedValueLengthOfDelayCompressionExtension,
            int providedCompressionMethodsClientToServerLength,
            String providedCompressionMethodsClientToServer,
            int providedCompressionMethodsServerToClientLength,
            String providedCompressionMethodsServerToClient) {
        ExtensionInfoMessage msg = new ExtensionInfoMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_EXT_INFO);
        msg.setExtensionCount(providedExtensionCount);

        ServerSigAlgsExtension serverSigAlgsExtension = new ServerSigAlgsExtension();
        serverSigAlgsExtension.setNameLength(providedNameLengthOfServerSigAlgsExtension);
        serverSigAlgsExtension.setName(providedNameOfServerSigAlgsExtension);
        serverSigAlgsExtension.setAcceptedPublicKeyAlgorithmsLength(
                providedValueLengthOfServerSigAlgsExtension);
        serverSigAlgsExtension.setAcceptedPublicKeyAlgorithms(
                providedValueOfServerSigAlgsExtension);
        msg.addExtension(serverSigAlgsExtension);

        DelayCompressionExtension delayCompressionExtension = new DelayCompressionExtension();
        delayCompressionExtension.setNameLength(providedNameLengthOfDelayCompressionExtension);
        delayCompressionExtension.setName(providedNameOfDelayCompressionExtension);
        delayCompressionExtension.setCompressionMethodsLength(
                providedValueLengthOfDelayCompressionExtension);
        delayCompressionExtension.setCompressionMethodsClientToServerLength(
                providedCompressionMethodsClientToServerLength);
        delayCompressionExtension.setCompressionMethodsClientToServer(
                providedCompressionMethodsClientToServer);
        delayCompressionExtension.setCompressionMethodsServerToClientLength(
                providedCompressionMethodsServerToClientLength);
        delayCompressionExtension.setCompressionMethodsServerToClient(
                providedCompressionMethodsServerToClient);
        msg.addExtension(delayCompressionExtension);

        ExtensionInfoMessageSerializer serializer = new ExtensionInfoMessageSerializer(msg);
        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
