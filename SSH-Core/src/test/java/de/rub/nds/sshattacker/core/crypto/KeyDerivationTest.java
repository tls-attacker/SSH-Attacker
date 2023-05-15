/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;

public class KeyDerivationTest {
    /**
     * Provides test vectors for the testDeriveKey unit test from SSH_Key_Derivation_Test.txt file
     *
     * @return A stream of test vectors for the testDeriveKey unit test
     */
    public static Stream<Arguments> provideKDFTestVectors() {
        InputStream testVectorFile =
                KeyDerivationTest.class
                        .getClassLoader()
                        .getResourceAsStream("SSH_Key_Derivation_Test.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String currentHashAlgorithm = null;
        Integer currentIvLength = null;
        Integer currentEncryptionLength = null;
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("[")) {
                currentHashAlgorithm = line.replace("[", "").replace("]", "");
                reader.nextLine();
                currentIvLength =
                        Integer.parseInt(
                                reader.nextLine().replace("[IV length = ", "").replace("]", ""));
                currentIvLength /= 8;
                currentEncryptionLength =
                        Integer.parseInt(
                                reader.nextLine()
                                        .replace("[encryption key length = ", "")
                                        .replace("]", ""));
                currentEncryptionLength /= 8;
            } else if (line.startsWith("COUNT")) {
                line = reader.nextLine();
                // Shared secret is stored as mpint (which has a 4 byte length prefix)
                byte[] sharedSecretMpint =
                        ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                byte[] sharedSecret =
                        Arrays.copyOfRange(sharedSecretMpint, 4, sharedSecretMpint.length);
                line = reader.nextLine();
                byte[] exchangeHash = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] sessionId = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyA = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyB = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyC = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyD = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyE = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] keyF = ArrayConverter.hexStringToByteArray(line.split(" = ")[1]);
                argumentsBuilder.add(
                        Arguments.of(
                                sharedSecret,
                                exchangeHash,
                                sessionId,
                                keyA,
                                keyB,
                                keyC,
                                keyD,
                                keyE,
                                keyF,
                                currentHashAlgorithm,
                                currentIvLength,
                                currentEncryptionLength));
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Test key derivation using KeyDerivation.deriveKey
     *
     * @param providedSharedSecret Shared secret from key exchange
     * @param providedExchangeHash Exchange hash value
     * @param providedSessionId Session ID
     * @param expectedKeyA Expected key with label A (client to server IV)
     * @param expectedKeyB Expected key with label B (server to client IV)
     * @param expectedKeyC Expected key with label C (client to server encryption key)
     * @param expectedKeyD Expected key with label D (server to client encryption key)
     * @param expectedKeyE Expected key with label E (client to server integrity key)
     * @param expectedKeyF Expected key with label F (server to client integrity key)
     */
    @ParameterizedTest
    @MethodSource("provideKDFTestVectors")
    public void testDeriveKey(
            byte[] providedSharedSecret,
            byte[] providedExchangeHash,
            byte[] providedSessionId,
            byte[] expectedKeyA,
            byte[] expectedKeyB,
            byte[] expectedKeyC,
            byte[] expectedKeyD,
            byte[] expectedKeyE,
            byte[] expectedKeyF,
            String providedHashAlgorithm,
            Integer providedIvLength,
            Integer providedEncryptionLength)
            throws NoSuchAlgorithmException {
        // Use of MessageDigest to get digest length
        MessageDigest digest = MessageDigest.getInstance(providedHashAlgorithm);

        byte[] keyA =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'A',
                        providedSessionId,
                        providedIvLength,
                        providedHashAlgorithm);
        byte[] keyB =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'B',
                        providedSessionId,
                        providedIvLength,
                        providedHashAlgorithm);
        byte[] keyC =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'C',
                        providedSessionId,
                        providedEncryptionLength,
                        providedHashAlgorithm);
        byte[] keyD =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'D',
                        providedSessionId,
                        providedEncryptionLength,
                        providedHashAlgorithm);
        byte[] keyE =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'E',
                        providedSessionId,
                        digest.getDigestLength(),
                        providedHashAlgorithm);
        byte[] keyF =
                KeyDerivation.deriveKey(
                        Converter.byteArrayToMpint(providedSharedSecret),
                        providedExchangeHash,
                        'F',
                        providedSessionId,
                        digest.getDigestLength(),
                        providedHashAlgorithm);

        assertArrayEquals(expectedKeyA, keyA);
        assertArrayEquals(expectedKeyB, keyB);
        assertArrayEquals(expectedKeyC, keyC);
        assertArrayEquals(expectedKeyD, keyD);
        assertArrayEquals(expectedKeyE, keyE);
        assertArrayEquals(expectedKeyF, keyF);
    }

    /** Test the computation of an ecdh exchange hash using the EcdhExchangeHash class */
    @Test
    public void testComputeECDHExchangeHash() throws CryptoException {
        VersionExchangeMessage clientVersion = new VersionExchangeMessage();
        clientVersion.setVersion("SSH-2.0-OpenSSH_7.9");
        clientVersion.setComment("");
        VersionExchangeMessage serverVersion = new VersionExchangeMessage();
        serverVersion.setVersion("SSH-2.0-OpenSSH_7.9");
        serverVersion.setComment("");

        EcdhKeyExchangeInitMessage ecdhInit =
                new EcdhKeyExchangeInitMessageParser(
                                ArrayConverter.hexStringToByteArray(
                                        "30000000207ca8902c60338482678b029a7b4484cb69e167922865c1217203dcb8050cd043"))
                        .parse();
        EcdhKeyExchangeReplyMessage ecdhReply =
                new EcdhKeyExchangeReplyMessageParser(
                                ArrayConverter.hexStringToByteArray(
                                        "31000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e065410000002020b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905000000630000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856"))
                        .parse();

        byte[] expectedHash =
                ArrayConverter.hexStringToByteArray(
                        "76ccc4d868fbce7a0b02b4545ccf01893ac034c73e8f7be3452fdf22360d6f3d");

        SshContext context = new SshContext();
        context.setKeyExchangeAlgorithm(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);
        ExchangeHashInputHolder inputHolder = new ExchangeHashInputHolder();

        inputHolder.setClientVersion(clientVersion);
        inputHolder.setServerVersion(serverVersion);
        inputHolder.setClientKeyExchangeInit(
                new KeyExchangeInitMessageParser(
                                ArrayConverter.hexStringToByteArray(
                                        "14c20497e7fc475072fd94347c70ef86260000010d637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d630000016665636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273610000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c696200000000000000000000000000"))
                        .parse());
        inputHolder.setServerKeyExchangeInit(
                new KeyExchangeInitMessageParser(
                                ArrayConverter.hexStringToByteArray(
                                        "147fe045782da34c08cbd3e03a6b4b4b1000000102637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d73686131000000417273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d00000000000000000000000000"))
                        .parse());
        inputHolder.setServerHostKey(
                PublicKeyHelper.parse(
                        PublicKeyFormat.ECDSA_SHA2_NISTP256,
                        ArrayConverter.hexStringToByteArray(
                                "0000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e06541")));
        inputHolder.setEcdhClientPublicKey(ecdhInit.getEphemeralPublicKey().getValue());
        inputHolder.setEcdhServerPublicKey(ecdhReply.getEphemeralPublicKey().getValue());
        inputHolder.setSharedSecret(
                ArrayConverter.hexStringToByteArray(
                        "13625c19127efdb1b15f1d5f48550760f29228342fbc438c06c56d795f31d109"));

        assertArrayEquals(
                expectedHash,
                ExchangeHash.computeEcdhHash(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256, inputHolder));
    }
}
