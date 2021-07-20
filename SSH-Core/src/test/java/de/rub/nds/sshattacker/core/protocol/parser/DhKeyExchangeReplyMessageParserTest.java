package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.DhKeyExchangeReplyMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DhKeyExchangeReplyMessageParserTest {
    /**
     * Provides a stream of test vectors for the DhKeyExchangeReplyMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream
                .of(Arguments.of(
                        ArrayConverter
                                .hexStringToByteArray("1F000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e06541" +
                                        "0000002020b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905000000630000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89" +
                                        "000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856"),
                        104,
                        0x13,
                        "ecdsa-sha2-nistp256",
                        32,
                        new BigInteger("20b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905", 16),
                        99,
                        ArrayConverter
                                .hexStringToByteArray("0000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856")));
    }

    /**
     * Test of DhKeyExchangeReplyMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedHostKeyLength
     *            Expected length of the host key
     * @param expectedHostKeyTypeLength
     *            Expected length of the host key type
     * @param expectedHostKeyType
     *            Expected host key type
     * @param expectedPublicKeyLength
     *            Expected length of the remote diffie hellman public key
     * @param expectedPublicKey
     *            Expected bytes of the remote diffie hellman public key
     * @param expectedSignatureLength
     *            Expected length of the signature
     * @param expectedSignature
     *            Expected bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedHostKeyLength, int expectedHostKeyTypeLength,
                          String expectedHostKeyType, int expectedPublicKeyLength,
                          BigInteger expectedPublicKey, int expectedSignatureLength, byte[] expectedSignature) {
        DhKeyExchangeReplyMessageParser parser = new DhKeyExchangeReplyMessageParser(0, providedBytes);
        DhKeyExchangeReplyMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_KEXDH_REPLY.id, msg.getMessageID().getValue());
        assertEquals(expectedHostKeyLength, msg.getHostKeyLength().getValue().intValue());
        assertEquals(expectedHostKeyTypeLength, msg.getHostKeyTypeLength().getValue().intValue());
        assertEquals(expectedHostKeyType, msg.getHostKeyType().getValue());
        // TODO: Add assertions for host key
        assertEquals(expectedPublicKeyLength, msg.getEphemeralPublicKeyLength().getValue().intValue());
        assertEquals(expectedPublicKey, msg.getEphemeralPublicKey().getValue());
        assertEquals(expectedSignatureLength, msg.getSignatureLength().getValue().intValue());
        assertArrayEquals(expectedSignature, msg.getSignature().getValue());
    }
}
