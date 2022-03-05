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
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaKeyExchangePubkeyMessageParserTest {
    /**
     * Provides a stream of test vectors for the RsaKeyExchangePubkeyMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "1E00000117000000077373682D727361000000030100010000010100CB1995285FDBDC4D21BB9902E08813C2AC571C1B844BD3DC8610A9B9EB175913885114FFAF622E2139E252CBD01808453CFFE2716A9462F12AEC9EF171B2CADEE8D6DC0E4586E69154D5087DACBE73C308CFE5F89B68AF018F260DCC66DB64AA8193BD3FFDCF39A1DA57A00942D75D1149D61277E94CFF2BC57B6EB9B6DA2B2858803EEB6F693E7CF9F104375A995785DFE6131111622A17E76B816F5CC676FF1B150300FCFDA91BADE225C6F4DA49075AC1AF1444FB7C0BE77EBBBA06C4E5D704BD951C2161F730CC2562544F2E1238060CC3406CC76615C53BA4B1A95B5034FFC92EF21F37A72A51DDA64FA85BCE09BA15E63D20706D6BEBC0E3164B741B3B00000117000000077373682D727361000000030100010000010100FD786F7BB51AC8B619430613F84251BEDEF47216786EE72025D02DC6E4FF923193E63DE937986925263360EBAF68990C73CA78B99EC24822FDB923461AD6925A4AD4EBAD370DA5B8AD9D9A4AD0E3E424043B7705D55DC52429D3DDD9F9F2E3DC618BF87C3519F5BB7C908C4B76CB72D366C5E32077E38DEF1780845BC950DFDF82C02CAFC1A8EE3535E491F33A8DC45EF515B56E305BC4BC124857D6662DB2C532840383F10C8EECA47029FC31143ACA4DE26C905E1291F778A6FBC0BDB219F775B33F3114C2ED1B64CC8E19ABC105305896778F7F686F82713E9198B19F70FF73674603B839B90ECE883D81DFB32DA3F9363A3207A639523F90EEE730B49F65"),
                        279, // Host Key Length
                        ArrayConverter.hexStringToByteArray(
                                "000000077373682D727361000000030100010000010100CB1995285FDBDC4D21BB9902E08813C2AC571C1B844BD3DC8610A9B9EB175913885114FFAF622E2139E252CBD01808453CFFE2716A9462F12AEC9EF171B2CADEE8D6DC0E4586E69154D5087DACBE73C308CFE5F89B68AF018F260DCC66DB64AA8193BD3FFDCF39A1DA57A00942D75D1149D61277E94CFF2BC57B6EB9B6DA2B2858803EEB6F693E7CF9F104375A995785DFE6131111622A17E76B816F5CC676FF1B150300FCFDA91BADE225C6F4DA49075AC1AF1444FB7C0BE77EBBBA06C4E5D704BD951C2161F730CC2562544F2E1238060CC3406CC76615C53BA4B1A95B5034FFC92EF21F37A72A51DDA64FA85BCE09BA15E63D20706D6BEBC0E3164B741B3B"),
                        279, // Transient Public Key Length
                        ArrayConverter.hexStringToByteArray(
                                "000000077373682D727361000000030100010000010100FD786F7BB51AC8B619430613F84251BEDEF47216786EE72025D02DC6E4FF923193E63DE937986925263360EBAF68990C73CA78B99EC24822FDB923461AD6925A4AD4EBAD370DA5B8AD9D9A4AD0E3E424043B7705D55DC52429D3DDD9F9F2E3DC618BF87C3519F5BB7C908C4B76CB72D366C5E32077E38DEF1780845BC950DFDF82C02CAFC1A8EE3535E491F33A8DC45EF515B56E305BC4BC124857D6662DB2C532840383F10C8EECA47029FC31143ACA4DE26C905E1291F778A6FBC0BDB219F775B33F3114C2ED1B64CC8E19ABC105305896778F7F686F82713E9198B19F70FF73674603B839B90ECE883D81DFB32DA3F9363A3207A639523F90EEE730B49F65"),
                        new BigInteger("010001", 16), // Exponent
                        new BigInteger(
                                "00FD786F7BB51AC8B619430613F84251BEDEF47216786EE72025D02DC6E4FF923193E63DE937986925263360EBAF68990C73CA78B99EC24822FDB923461AD6925A4AD4EBAD370DA5B8AD9D9A4AD0E3E424043B7705D55DC52429D3DDD9F9F2E3DC618BF87C3519F5BB7C908C4B76CB72D366C5E32077E38DEF1780845BC950DFDF82C02CAFC1A8EE3535E491F33A8DC45EF515B56E305BC4BC124857D6662DB2C532840383F10C8EECA47029FC31143ACA4DE26C905E1291F778A6FBC0BDB219F775B33F3114C2ED1B64CC8E19ABC105305896778F7F686F82713E9198B19F70FF73674603B839B90ECE883D81DFB32DA3F9363A3207A639523F90EEE730B49F65",
                                16) // Modulus
                        ));
    }

    /**
     * Test of RsaKeyExchangePubkeyMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedHostKeyLength Expected length of the host key
     * @param expectedHostKey Expected bytes of the host key
     * @param expectedTransientPubkeyLength Expected length of the transient public key
     * @param expectedTransientPubkey Expected bytes of the transient public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedHostKeyLength,
            byte[] expectedHostKey,
            int expectedTransientPubkeyLength,
            byte[] expectedTransientPubkey,
            BigInteger exponent,
            BigInteger modulus) {
        RsaKeyExchangePubkeyMessageParser parser =
                new RsaKeyExchangePubkeyMessageParser(providedBytes, 0);
        RsaKeyExchangePubkeyMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_KEXRSA_PUBKEY.id, msg.getMessageID().getValue());
        assertEquals(expectedHostKeyLength, msg.getHostKeyLength().getValue().intValue());
        assertArrayEquals(expectedHostKey, msg.getHostKey().getValue());
        assertEquals(
                expectedTransientPubkeyLength,
                msg.getTransientPubkeyLength().getValue().intValue());
        assertArrayEquals(expectedTransientPubkey, msg.getTransientPubkey().getValue());
        assertEquals(exponent, msg.getExponent().getValue());
        assertEquals(modulus, msg.getModulus().getValue());
    }
}
