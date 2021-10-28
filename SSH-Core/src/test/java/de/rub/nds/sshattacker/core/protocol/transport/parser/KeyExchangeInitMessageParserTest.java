/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyExchangeInitMessageParserTest {
    /**
     * Provides a stream of test vectors for the KeyExchangeInitMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "14e0b018941e57551ede3fde36a71e08080000007a637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235360000000f7373682d6473732c7373682d7273610000005f63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d6374722c6165733139322d6374722c6165733132382d6374722c6165733235362d6362632c6165733139322d6362632c6165733132382d6362630000005f63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d6374722c6165733139322d6374722c6165733132382d6374722c6165733235362d6362632c6165733139322d6362632c6165733132382d63626300000025686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d7368613100000025686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c69622c7a6c6962406f70656e7373682e636f6d0000001a6e6f6e652c7a6c69622c7a6c6962406f70656e7373682e636f6d00000000000000000000000000"),
                        ArrayConverter.hexStringToByteArray("e0b018941e57551ede3fde36a71e0808"),
                        122,
                        "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256",
                        15,
                        "ssh-dss,ssh-rsa",
                        95,
                        "chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc",
                        95,
                        "chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc",
                        37,
                        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                        37,
                        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                        26,
                        "none,zlib,zlib@openssh.com",
                        26,
                        "none,zlib,zlib@openssh.com",
                        0,
                        "",
                        0,
                        "",
                        (byte) 0x00,
                        0x00000000),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "14fbf207980a5e1f64469ee7dad6593e070000010d637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d63000001667273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c696200000000000000000000000000"),
                        ArrayConverter.hexStringToByteArray("fbf207980a5e1f64469ee7dad6593e07"),
                        269,
                        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
                        358,
                        "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519",
                        108,
                        "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
                        108,
                        "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
                        213,
                        "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                        213,
                        "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                        26,
                        "none,zlib@openssh.com,zlib",
                        26,
                        "none,zlib@openssh.com,zlib",
                        0,
                        "",
                        0,
                        "",
                        (byte) 0x00,
                        0x00000000));
    }

    /**
     * Test of KeyExchangeInitMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedCookie Expected bytes of the cookie
     * @param expectedKeyExchangeAlgorithmsLength Expected length of the key exchange algorithm list
     * @param expectedKeyExchangeAlgorithms Expected key exchange algorithm list
     * @param expectedServerHostKeyAlgorithmsLength Expected length of the host key algorithm list
     * @param expectedServerHostKeyAlgorithms Expected host key algorithm list
     * @param expectedEncryptionAlgorithmsCToSLength Expected length of the encryption algorithm
     *     list (client to server)
     * @param expectedEncryptionAlgorithmsCToS Expected encryption algorithm list (client to server)
     * @param expectedEncryptionAlgorithmsSToCLength Expected length of the encryption algorithm
     *     list (server to client)
     * @param expectedEncryptionAlgorithmsSToC Expected encryption algorithm list (server to client)
     * @param expectedMacAlgorithmsCToSLength Expected length of the MAC algorithm list (client to
     *     server)
     * @param expectedMacAlgorithmsCToS Expected MAC algorithm list (client to server)
     * @param expectedMacAlgorithmsSToCLength Expected length of the MAC algorithm list (server to
     *     client)
     * @param expectedMacAlgorithmsSToC Expected MAC algorithm list (server to client)
     * @param expectedCompressionAlgorithmsCToSLength Expected length of the compression algorithm
     *     list (client to server)
     * @param expectedCompressionAlgorithmsCToS Expected compression algorithm list (client to
     *     server)
     * @param expectedCompressionAlgorithmsSToCLength Expected length of the compression algorithm
     *     list (server to client)
     * @param expectedCompressionAlgorithmsSToC Expected compression algorithm list (server to
     *     client)
     * @param expectedLanguagesCToSLength Expected length of the list of languages (client to
     *     server)
     * @param expectedLanguagesCToS Expected list of languages (client to server)
     * @param expectedLanguagesSToCLength Expected length of the list of languages (server to
     *     client)
     * @param expectedLanguagesSToC Expected list of languages (server to client)
     * @param expectedFirstKeyExchangePacketFollows Expected value of the
     *     firstKeyExchangePacketFollows field
     * @param expectedReserved Expected value of the reserved field
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            byte[] expectedCookie,
            int expectedKeyExchangeAlgorithmsLength,
            String expectedKeyExchangeAlgorithms,
            int expectedServerHostKeyAlgorithmsLength,
            String expectedServerHostKeyAlgorithms,
            int expectedEncryptionAlgorithmsCToSLength,
            String expectedEncryptionAlgorithmsCToS,
            int expectedEncryptionAlgorithmsSToCLength,
            String expectedEncryptionAlgorithmsSToC,
            int expectedMacAlgorithmsCToSLength,
            String expectedMacAlgorithmsCToS,
            int expectedMacAlgorithmsSToCLength,
            String expectedMacAlgorithmsSToC,
            int expectedCompressionAlgorithmsCToSLength,
            String expectedCompressionAlgorithmsCToS,
            int expectedCompressionAlgorithmsSToCLength,
            String expectedCompressionAlgorithmsSToC,
            int expectedLanguagesCToSLength,
            String expectedLanguagesCToS,
            int expectedLanguagesSToCLength,
            String expectedLanguagesSToC,
            byte expectedFirstKeyExchangePacketFollows,
            int expectedReserved) {
        KeyExchangeInitMessageParser parser = new KeyExchangeInitMessageParser(providedBytes, 0);
        KeyExchangeInitMessage msg = parser.parse();

        assertArrayEquals(expectedCookie, msg.getCookie().getValue());
        assertEquals(
                expectedKeyExchangeAlgorithmsLength,
                msg.getKeyExchangeAlgorithmsLength().getValue().intValue());
        assertEquals(expectedKeyExchangeAlgorithms, msg.getKeyExchangeAlgorithms().getValue());
        assertEquals(
                expectedServerHostKeyAlgorithmsLength,
                msg.getServerHostKeyAlgorithmsLength().getValue().intValue());
        assertEquals(expectedServerHostKeyAlgorithms, msg.getServerHostKeyAlgorithms().getValue());
        assertEquals(
                expectedEncryptionAlgorithmsCToSLength,
                msg.getEncryptionAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(
                expectedEncryptionAlgorithmsCToS,
                msg.getEncryptionAlgorithmsClientToServer().getValue());
        assertEquals(
                expectedEncryptionAlgorithmsSToCLength,
                msg.getEncryptionAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(
                expectedEncryptionAlgorithmsSToC,
                msg.getEncryptionAlgorithmsServerToClient().getValue());
        assertEquals(
                expectedMacAlgorithmsCToSLength,
                msg.getMacAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(expectedMacAlgorithmsCToS, msg.getMacAlgorithmsClientToServer().getValue());
        assertEquals(
                expectedMacAlgorithmsSToCLength,
                msg.getMacAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(expectedMacAlgorithmsSToC, msg.getMacAlgorithmsServerToClient().getValue());
        assertEquals(
                expectedCompressionAlgorithmsCToSLength,
                msg.getCompressionAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(
                expectedCompressionAlgorithmsCToS,
                msg.getCompressionAlgorithmsClientToServer().getValue());
        assertEquals(
                expectedCompressionAlgorithmsSToCLength,
                msg.getCompressionAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(
                expectedCompressionAlgorithmsSToC,
                msg.getCompressionAlgorithmsServerToClient().getValue());
        assertEquals(
                expectedLanguagesCToSLength,
                msg.getLanguagesClientToServerLength().getValue().intValue());
        assertEquals(expectedLanguagesCToS, msg.getLanguagesClientToServer().getValue());
        assertEquals(
                expectedLanguagesSToCLength,
                msg.getLanguagesServerToClientLength().getValue().intValue());
        assertEquals(expectedLanguagesSToC, msg.getLanguagesServerToClient().getValue());
        assertEquals(
                expectedFirstKeyExchangePacketFollows,
                msg.getFirstKeyExchangePacketFollows().getValue());
        assertEquals(expectedReserved, msg.getReserved().getValue().intValue());
    }
}
