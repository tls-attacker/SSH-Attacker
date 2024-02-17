/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchangeTest;
import jakarta.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class JavaMacTest {

    public static Stream<Arguments> provideSha1TestVectors() {
        InputStream testVectorFile =
                EcdhKeyExchangeTest.class
                        .getClassLoader()
                        .getResourceAsStream("hmac-sha1-testvectors.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("test_case")) {
                line = reader.nextLine();
                byte[] key = DatatypeConverter.parseHexBinary(line.split("x")[1]);
                reader.nextLine();
                line = reader.nextLine();
                String data = line.split("\"")[1];
                byte[] message = data.getBytes();
                reader.nextLine();
                line = reader.nextLine();
                byte[] hmac = DatatypeConverter.parseHexBinary(line.split("x")[1]);
                argumentsBuilder.add(Arguments.of(MacAlgorithm.HMAC_SHA1, key, message, hmac));
            }
        }
        return argumentsBuilder.build();
    }

    public static Stream<Arguments> provideSha2TestVectors() {
        InputStream testVectorFile =
                EcdhKeyExchangeTest.class
                        .getClassLoader()
                        .getResourceAsStream("hmac-sha2-testvectors.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("Key")) {
                byte[] key = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] data = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                reader.nextLine();
                line = reader.nextLine();
                byte[] sha256 = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                argumentsBuilder.add(Arguments.of(MacAlgorithm.HMAC_SHA2_256, key, data, sha256));
                reader.nextLine();
                line = reader.nextLine();
                byte[] sha512 = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                argumentsBuilder.add(Arguments.of(MacAlgorithm.HMAC_SHA2_512, key, data, sha512));
            }
        }

        return argumentsBuilder.build();
    }

    /**
     * Tests the class JavaMac with the hmac-sha1, hmac-sha2-256 and hmac-sha2-512 mac algorithm.
     * Bypasses the specific sequenceNumber computation of SSH by using the first 4 bytes as
     * virtualSequenceNumbers, because they are concatenated later on and the vector generation
     * didn't follow the specification.
     *
     * @param algorithm the mac algorithm to use
     * @param key input key
     * @param message message to authenticate
     * @param hmac computed hmac tag
     */
    @ParameterizedTest
    @MethodSource({"provideSha1TestVectors", "provideSha2TestVectors"})
    public void testShaHMac(MacAlgorithm algorithm, byte[] key, byte[] message, byte[] hmac) {
        Security.addProvider(new BouncyCastleProvider());
        JavaMac macInstance = new JavaMac(algorithm, key);
        int virtualSequenceNumber = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, 0, 4));
        byte[] calculatedTag =
                macInstance.calculate(
                        virtualSequenceNumber, Arrays.copyOfRange(message, 4, message.length));
        assertEquals(algorithm, macInstance.getAlgorithm());
        assertArrayEquals(hmac, calculatedTag);
    }
}
