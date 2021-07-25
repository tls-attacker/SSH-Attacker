/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

import java.util.stream.Stream;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class EcdhKeyExchangeReplyMessageParserTest {
    /**
     * Provides a stream of test vectors for the EcdhKeyExchangeReplyMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream
                .of(Arguments.of(
                        ArrayConverter
                                .hexStringToByteArray("1F000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e065410000002020b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905000000630000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856"),
                        104,
                        0x13,
                        "ecdsa-sha2-nistp256",
                        8,
                        "nistp256",
                        65,
                        ArrayConverter
                                .hexStringToByteArray("0435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e06541"),
                        32,
                        ArrayConverter
                                .hexStringToByteArray("20b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905"),
                        99,
                        ArrayConverter
                                .hexStringToByteArray("0000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856")));
    }

    /**
     * Test of EcdhKeyExchangeReplyMessageParser::parse method
     * 
     * @param providedBytes
     *            Bytes to parse
     * @param expectedHostKeyLength
     *            Expected length of the host key
     * @param expectedHostKeyTypeLength
     *            Expected length of the host key type
     * @param expectedHostKeyType
     *            Expected host key type
     * @param expectedEccCurveIdentifierLength
     *            Expected length of the ECC curve identifier
     * @param expectedEccCurveIdentifier
     *            Expected ECC curve identifier
     * @param expectedEccHostKeyLength
     *            Expected ECC host key length
     * @param expectedEccHostKey
     *            Expected ECC host key
     * @param expectedPublicKeyLength
     *            Expected length of the remote ECDH public key
     * @param expectedPublicKey
     *            Expected bytes of the remote ECDH public key
     * @param expectedSignatureLength
     *            Expected length of the signature
     * @param expectedSignature
     *            Expected bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedHostKeyLength, int expectedHostKeyTypeLength,
            String expectedHostKeyType, int expectedEccCurveIdentifierLength, String expectedEccCurveIdentifier,
            int expectedEccHostKeyLength, byte[] expectedEccHostKey, int expectedPublicKeyLength,
            byte[] expectedPublicKey, int expectedSignatureLength, byte[] expectedSignature) {
        EcdhKeyExchangeReplyMessageParser parser = new EcdhKeyExchangeReplyMessageParser(0, providedBytes);
        EcdhKeyExchangeReplyMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY.id, msg.getMessageID().getValue());
        assertEquals(expectedHostKeyLength, msg.getHostKeyLength().getValue().intValue());
        assertEquals(expectedHostKeyTypeLength, msg.getHostKeyTypeLength().getValue().intValue());
        assertEquals(expectedHostKeyType, msg.getHostKeyType().getValue());
        assertEquals(expectedEccCurveIdentifierLength, msg.getEccCurveIdentifierLength().getValue().intValue());
        assertEquals(expectedEccCurveIdentifier, msg.getEccCurveIdentifier().getValue());
        assertEquals(expectedEccHostKeyLength, msg.getHostKeyEccLength().getValue().intValue());
        assertArrayEquals(expectedEccHostKey, msg.getHostKeyEcc().getValue());
        assertEquals(expectedPublicKeyLength, msg.getEphemeralPublicKeyLength().getValue().intValue());
        assertArrayEquals(expectedPublicKey, msg.getEphemeralPublicKey().getValue());
        assertEquals(expectedSignatureLength, msg.getSignatureLength().getValue().intValue());
        assertArrayEquals(expectedSignature, msg.getSignature().getValue());
    }
}
