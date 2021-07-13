/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.parser.EcdhKeyExchangeReplyMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class EcdhKeyExchangeReplyMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the EcdhKeyExchangeReplyMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return EcdhKeyExchangeReplyMessageParserTest.provideTestVectors();
    }

    /**
     * Test of EcdhKeyExchangeReplyMessageSerializer::serialize method
     * 
     * @param expectedBytes
     *            Expected output of the serialize() call
     * @param providedHostKeyLength
     *            Length of the host key
     * @param providedHostKeyTypeLength
     *            Length of the host key type
     * @param providedHostKeyType
     *            Host key type
     * @param providedEccCurveIdentifierLength
     *            Length of the ECC curve identifier
     * @param providedEccCurveIdentifier
     *            ECC curve identifier
     * @param providedEccHostKeyLength
     *            Length of the ECC host key
     * @param providedEccHostKey
     *            Bytes of the ECC host key
     * @param providedPublicKeyLength
     *            Length of the RSA host key
     * @param providedPublicKey
     *            Bytes of the RSA host key
     * @param providedSignatureLength
     *            Length of the signature
     * @param providedSignature
     *            Bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedHostKeyLength, int providedHostKeyTypeLength,
            String providedHostKeyType, int providedEccCurveIdentifierLength, String providedEccCurveIdentifier,
            int providedEccHostKeyLength, byte[] providedEccHostKey, int providedPublicKeyLength,
            byte[] providedPublicKey, int providedSignatureLength, byte[] providedSignature) {
        EcdhKeyExchangeReplyMessage msg = new EcdhKeyExchangeReplyMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY.id);
        msg.setHostKeyLength(providedHostKeyLength);
        msg.setHostKeyTypeLength(providedHostKeyTypeLength);
        msg.setHostKeyType(providedHostKeyType);
        msg.setEccCurveIdentifierLength(providedEccCurveIdentifierLength);
        msg.setEccCurveIdentifier(providedEccCurveIdentifier);
        msg.setHostKeyEccLength(providedEccHostKeyLength);
        msg.setHostKeyEcc(providedEccHostKey);
        msg.setPublicKeyLength(providedPublicKeyLength);
        msg.setPublicKey(providedPublicKey);
        msg.setSignatureLength(providedSignatureLength);
        msg.setSignature(providedSignature);
        EcdhKeyExchangeReplyMessageSerializer serializer = new EcdhKeyExchangeReplyMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
