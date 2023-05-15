/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class NoneCipherTest {

    public static Stream<Arguments> provideVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "DD68298BCAE4493C7979050ED3E18028FE0ABC4EE072D67F3109411873F8A3B21B773B1B383A0A71CC481E662635D1A178AC")),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "26ECE68A2E067E4425D2238B09CA1182B928BE4945EFDB919AD22B1AB8F9FAA4")));
    }

    public static Stream<Arguments> provideVectors1() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("2F611CB1388EE716D4BE37CCD7398E70"),
                        ArrayConverter.hexStringToByteArray("07D966F0FF851A8D")),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "83820C599AE87891F77B7C57B61783D7B58237B91AED1BF39509B9AC1F090305796F46E3C3AA45AB499919F5E2289F29CBEB"),
                        ArrayConverter.hexStringToByteArray("42DC27517AC6466532FD5EAB")));
    }

    public static Stream<Arguments> provideVectors2() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("85FEDFA742EE5C9A7FF3A850ABA0E9A6"),
                        ArrayConverter.hexStringToByteArray("03D452CD3F1973CC"),
                        ArrayConverter.hexStringToByteArray("A038A139CC9B01FC61941467")),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "DB4D1F1138025982C835822EB69AC152AD68F89C77DF67C24F15C195DA9804D7C757FD9CFAEDA54B5BFFBE4939E8F5B8C0B7"),
                        ArrayConverter.hexStringToByteArray("E2C19C2F769DDC83CA85CEF8"),
                        ArrayConverter.hexStringToByteArray("F2B0506F574C5772")));
    }

    /**
     * Tests the encryption and decryption of the NoneCipher with only the plaintext as input.
     *
     * @param data data to be encrypted/decrypted
     */
    @ParameterizedTest
    @MethodSource("provideVectors")
    public void testNoneCipher(byte[] data) {
        NoneCipher cipher = new NoneCipher();
        assertEquals(EncryptionAlgorithm.NONE, cipher.getAlgorithm());
        assertArrayEquals(data, cipher.encrypt(data));
        assertArrayEquals(data, cipher.decrypt(data));
    }

    /**
     * Tests the encryption and decryption of the NoneCipher with the plaintext and an initial
     * vector.
     *
     * @param data data to be encrypted/decrypted
     * @param iv initial vector
     */
    @ParameterizedTest
    @MethodSource("provideVectors1")
    public void testNoneCipher(byte[] data, byte[] iv) {
        NoneCipher cipher = new NoneCipher();
        assertEquals(EncryptionAlgorithm.NONE, cipher.getAlgorithm());
        assertArrayEquals(data, cipher.encrypt(data, iv));
        assertArrayEquals(data, cipher.decrypt(data, iv));
    }

    /**
     * Tests the encryption and decryption of the NoneCipher with the plaintext, an initial vector
     * and additional authentication data.
     *
     * @param data data to be encrypted/decrypted
     * @param iv initial vector
     * @param aad additional authentication data
     */
    @ParameterizedTest
    @MethodSource("provideVectors2")
    public void testNoneCipher(byte[] data, byte[] iv, byte[] aad) {
        NoneCipher cipher = new NoneCipher();
        assertEquals(EncryptionAlgorithm.NONE, cipher.getAlgorithm());
        assertArrayEquals(data, cipher.encrypt(data, iv, aad));
        assertArrayEquals(data, cipher.decrypt(data, iv, aad));
    }
}
