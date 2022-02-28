/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaKeyExchangeDoneMessageParserTest {
    /**
     * Provides a stream of test vectors for the RsaKeyExchangeDoneMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "200000010F000000077373682D727361000001002225F10C9A6AE204048DDE969C3E8B18EADF17CC912CF599E34176087CCF0877D3B1AC70EBA35B3DA5ABA15AB3A357460D69CF78441A1836021A8660D9E470C50092B7E38C5AC35E7CD0BA1CAF9509BC492C4A625AB3472C5AA395A496EA1C54C91164CDA14CB30897D32768A0B4545DB0B310001801D5D3DCB9E405F31121427AEB6A2B27DC59C531C42726B1DE84641E69B4E20F6BF91A52C8B56E88AFAEB51D7CFA627E4FE52664FB0EA573DE06A0E528AFBDF9A3AE4884532CFDDDA05A064F3CD7B76F5C2ADC194C88B748F3F27038BEBBCE7DAAC9B54EF1840250E27FB558A37A039A40D7E8E7A0BBEDC735144C49EC7506E3EF61C7C2E17580C63395D2"),
                        271, // Signature Length
                        ArrayConverter.hexStringToByteArray(
                                "000000077373682D727361000001002225F10C9A6AE204048DDE969C3E8B18EADF17CC912CF599E34176087CCF0877D3B1AC70EBA35B3DA5ABA15AB3A357460D69CF78441A1836021A8660D9E470C50092B7E38C5AC35E7CD0BA1CAF9509BC492C4A625AB3472C5AA395A496EA1C54C91164CDA14CB30897D32768A0B4545DB0B310001801D5D3DCB9E405F31121427AEB6A2B27DC59C531C42726B1DE84641E69B4E20F6BF91A52C8B56E88AFAEB51D7CFA627E4FE52664FB0EA573DE06A0E528AFBDF9A3AE4884532CFDDDA05A064F3CD7B76F5C2ADC194C88B748F3F27038BEBBCE7DAAC9B54EF1840250E27FB558A37A039A40D7E8E7A0BBEDC735144C49EC7506E3EF61C7C2E17580C63395D2")));
    }

    /**
     * Test of RsaKeyExchangePubkeyMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedSignatureLength Expected length of the signature
     * @param expectedSignature Expected bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes, int expectedSignatureLength, byte[] expectedSignature) {
        RsaKeyExchangeDoneMessageParser parser =
                new RsaKeyExchangeDoneMessageParser(providedBytes, 0);
        RsaKeyExchangeDoneMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_KEXRSA_DONE.id, msg.getMessageID().getValue());
        assertEquals(expectedSignatureLength, msg.getSignatureLength().getValue().intValue());
        assertArrayEquals(expectedSignature, msg.getSignature().getValue());
    }
}
