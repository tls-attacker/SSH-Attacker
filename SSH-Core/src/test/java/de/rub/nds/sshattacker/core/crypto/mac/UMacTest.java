/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("StandardVariableNames")
public class UMacTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        "".getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("113145FB"),
                        ArrayConverter.hexStringToByteArray("6E155FAD26900BE1"),
                        ArrayConverter.hexStringToByteArray("32FEDB100C79AD58F07FF764")),
                Arguments.of(
                        "a".repeat(3).getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("3B91D102"),
                        ArrayConverter.hexStringToByteArray("44B5CB542F220104"),
                        ArrayConverter.hexStringToByteArray("185E4FE905CBA7BD85E4C2DC")),
                Arguments.of(
                        "a".repeat(1 << 10).getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("599B350B"),
                        ArrayConverter.hexStringToByteArray("26BF2F5D60118BD9"),
                        ArrayConverter.hexStringToByteArray("7A54ABE04AF82D60FB298C3C")),
                Arguments.of(
                        "a".repeat(1 << 15).getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("58DCF532"),
                        ArrayConverter.hexStringToByteArray("27F8EF643B0D118D"),
                        ArrayConverter.hexStringToByteArray("7B136BD911E4B734286EF2BE")),
                Arguments.of(
                        "a".repeat(1 << 20).getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("DB6364D1"),
                        ArrayConverter.hexStringToByteArray("A4477E87E9F55853"),
                        ArrayConverter.hexStringToByteArray("F8ACFA3AC31CFEEA047F7B11")),
                Arguments.of(
                        "abc".getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("ABF3A3A0"),
                        ArrayConverter.hexStringToByteArray("D4D7B9F6BD4FBFCF"),
                        ArrayConverter.hexStringToByteArray("883C3D4B97A61976FFCF2323")),
                Arguments.of(
                        "abc".repeat(500).getBytes(StandardCharsets.US_ASCII),
                        ArrayConverter.hexStringToByteArray("ABEB3C8B"),
                        ArrayConverter.hexStringToByteArray("D4CF26DDEFD5C01A"),
                        ArrayConverter.hexStringToByteArray("8824A260C53C66A36C9260A6")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testUMac(
            byte[] M, byte[] expectedTag32, byte[] expectedTag64, byte[] expectedTag96) {
        byte[] K = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
        byte[] N = "bcdefghi".getBytes(StandardCharsets.US_ASCII);
        byte[] actualTag32 = UMac.UMAC32(K, M, N);
        byte[] actualTag64 = UMac.UMAC64(K, M, N);
        byte[] actualTag96 = UMac.UMAC96(K, M, N);
        Assertions.assertArrayEquals(expectedTag32, actualTag32);
        Assertions.assertArrayEquals(expectedTag64, actualTag64);
        Assertions.assertArrayEquals(expectedTag96, actualTag96);
    }

    @Test
    public void testUHash() {
        byte[] K = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
        byte[] M = "abc".repeat(500).getBytes(StandardCharsets.US_ASCII);
        int taglen = 8;
        byte[] expectedHash = ArrayConverter.hexStringToByteArray("05F86309DF9AD858");
        byte[] actualHash = UMac.UHASH(K, M, taglen);
        Assertions.assertArrayEquals(expectedHash, actualHash);
    }

    @Test
    public void testKDFForL1() {
        // Test vectors are taken from RFC 4418 Appendix
        byte[] K = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
        int taglen = 8;
        int iters = taglen / 4;

        byte[] L1Key = UMac.KDF(K, 1, 1024 + (iters - 1) * 16);
        byte[][] L1Key_ = new byte[iters][];
        for (int i = 0; i < iters; i++) {
            L1Key_[i] = Arrays.copyOfRange(L1Key, i * 16, i * 16 + 1024);
        }

        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("ACD79B4F6EDA0D0E1625B60384F9FC93C6DFECA2"),
                Arrays.copyOfRange(L1Key_[0], 0, 20));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0BF0F56C"),
                Arrays.copyOfRange(L1Key_[0], 1020, 1024));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("C6DFECA2964A710DAD7EDE4DA1D3935E62EC8672"),
                Arrays.copyOfRange(L1Key_[1], 0, 20));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("744C294F"),
                Arrays.copyOfRange(L1Key_[1], 1020, 1024));
    }

    @Test
    public void testKDFForL2() {
        // Test vectors are taken from RFC 4418 Appendix
        byte[] K = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
        int taglen = 8;
        int iters = taglen / 4;

        byte[] L2Key = UMac.KDF(K, 2, iters * 24);
        byte[][] L2Key_ = new byte[iters][];
        for (int i = 0; i < iters; i++) {
            L2Key_[i] = Arrays.copyOfRange(L2Key, i * 24, (i + 1) * 24);
        }

        // L2 key64 is masked (only masked test vectors are given by the RFC)
        byte[] Mask64 = ArrayConverter.hexStringToByteArray("01ffffff01ffffff");
        byte[][] k64 = new byte[iters][8];
        for (int i = 0; i < iters; i++) {
            for (int j = 0; j < 8; j++) {
                k64[i][j] = (byte) (L2Key_[i][j] & Mask64[j]);
            }
        }
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0094B8DD0137BEF8"), k64[0]);
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("01036F4D000E7E72"), k64[1]);
    }

    @Test
    public void testKDFForL3() {
        // Test vectors are taken from RFC 4418 Appendix
        byte[] K = "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII);
        int taglen = 8;
        int iters = taglen / 4;

        byte[] L3Key1 = UMac.KDF(K, 3, iters * 64);
        byte[] L3Key2 = UMac.KDF(K, 4, iters * 4);
        byte[][] L3Key1_ = new byte[iters][];
        byte[][] L3Key2_ = new byte[iters][];
        for (int i = 0; i < iters; i++) {
            L3Key1_[i] = Arrays.copyOfRange(L3Key1, i * 64, (i + 1) * 64);
            L3Key2_[i] = Arrays.copyOfRange(L3Key2, i * 4, (i + 1) * 4);
        }

        // L3 modulo reduces K1 chunk-wise by prime(36), only the reduced test vectors are given
        byte[][][] K_ = new byte[iters][8][];
        BigInteger[][] k_ = new BigInteger[iters][8];
        for (int i = 0; i < iters; i++) {
            for (int j = 0; j < 8; j++) {
                K_[i][j] = Arrays.copyOfRange(L3Key1_[i], 8 * j, 8 * (j + 1));
                k_[i][j] = new BigInteger(1, K_[i][j]).mod(UMac.prime(36));
            }
        }
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("056533C3A8"),
                ArrayConverter.bigIntegerToByteArray(k_[0][4]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("07591E062E"),
                ArrayConverter.bigIntegerToByteArray(k_[0][5]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0C2D30F89D"),
                ArrayConverter.bigIntegerToByteArray(k_[0][6]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("046786437C"),
                ArrayConverter.bigIntegerToByteArray(k_[0][7]));
        Assertions.assertArrayEquals(ArrayConverter.hexStringToByteArray("2E79F461"), L3Key2_[0]);
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0504BF4D4E"),
                ArrayConverter.bigIntegerToByteArray(k_[1][4]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0126E922FF"),
                ArrayConverter.bigIntegerToByteArray(k_[1][5]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("030C0399E2"),
                ArrayConverter.bigIntegerToByteArray(k_[1][6]));
        Assertions.assertArrayEquals(
                ArrayConverter.hexStringToByteArray("04C1CB8FED"),
                ArrayConverter.bigIntegerToByteArray(k_[1][7]));
        Assertions.assertArrayEquals(ArrayConverter.hexStringToByteArray("A74C03AA"), L3Key2_[1]);
    }

    @Test
    public void testEndianSwap() {
        byte[] littleEndian = {
            (byte) 0x00,
            (byte) 0xAB,
            (byte) 0xBC,
            (byte) 0xCD,
            (byte) 0x00,
            (byte) 0x12,
            (byte) 0x23,
            (byte) 0x34
        };
        byte[] bigEndian = {
            (byte) 0xCD,
            (byte) 0xBC,
            (byte) 0xAB,
            (byte) 0x00,
            (byte) 0x34,
            (byte) 0x23,
            (byte) 0x12,
            (byte) 0x00
        };
        Assertions.assertArrayEquals(bigEndian, UMac.ENDIAN_SWAP(littleEndian));
    }

    @Test
    public void testAdd32Identity() {
        byte[] a = ArrayConverter.intToBytes(0xABCDEF00, 4);
        byte[] zero = ArrayConverter.intToBytes(0, 4);
        byte[] actualSum = UMac.add32(a, zero);
        Assertions.assertArrayEquals(a, actualSum);
    }

    @Test
    public void testAdd32NoOverflow() {
        byte[] a = ArrayConverter.intToBytes(0xABCDEF00, 4);
        byte[] b = ArrayConverter.intToBytes(0x00EFCDAB, 4);
        byte[] expectedSum = ArrayConverter.intToBytes(0xACBDBCAB, 4);
        byte[] actualSum = UMac.add32(a, b);
        Assertions.assertArrayEquals(expectedSum, actualSum);
    }

    @Test
    public void testAdd32Overflow() {
        byte[] a = ArrayConverter.intToBytes(0xABCDEF00, 4);
        byte[] expectedSum = ArrayConverter.intToBytes(0x579BDE00, 4);
        byte[] actualSum = UMac.add32(a, a);
        Assertions.assertArrayEquals(expectedSum, actualSum);
    }

    @Test
    public void testAdd64Identity() {
        byte[] a = ArrayConverter.longToEightBytes(0xABCDEF00ABCDEF00L);
        byte[] zero = ArrayConverter.longToEightBytes(0);
        byte[] actualSum = UMac.add64(a, zero);
        Assertions.assertArrayEquals(a, actualSum);
    }

    @Test
    public void testAdd64NoOverflow() {
        byte[] a = ArrayConverter.longToEightBytes(0xABCDEF00ABCDEF00L);
        byte[] b = ArrayConverter.longToEightBytes(0x0123456789ABCDEFL);
        byte[] expectedSum = ArrayConverter.longToEightBytes(0xACF134683579BCEFL);
        byte[] actualSum = UMac.add64(a, b);
        Assertions.assertArrayEquals(actualSum, expectedSum);
    }

    @Test
    public void testAdd64Overflow() {
        byte[] a = ArrayConverter.longToEightBytes(0xABCDEF00ABCDEF00L);
        byte[] expectedSum = ArrayConverter.longToEightBytes(0x579BDE01579BDE00L);
        byte[] actualSum = UMac.add64(a, a);
        Assertions.assertArrayEquals(actualSum, expectedSum);
    }

    @Test
    public void testMult64Identity() {
        byte[] a = ArrayConverter.longToEightBytes(0xDEADC0DEL);
        byte[] one = ArrayConverter.longToEightBytes(1L);
        byte[] actualProduct = UMac.mult64(a, one);
        Assertions.assertArrayEquals(a, actualProduct);
    }

    @Test
    public void testMult64NoOverflow() {
        byte[] a = ArrayConverter.longToEightBytes(0xDEADC0DEL);
        byte[] b = ArrayConverter.longToEightBytes(0xC0DEL);
        byte[] expectedProduct = ArrayConverter.longToEightBytes(0xA7C36B53C084L);
        byte[] actualProduct = UMac.mult64(a, b);
        Assertions.assertArrayEquals(expectedProduct, actualProduct);
    }

    @Test
    public void testMult64WithOverflow() {
        byte[] a = ArrayConverter.longToEightBytes(0xDEADC0DEDEADC0DEL);
        byte[] expectedProduct = ArrayConverter.longToEightBytes(0x4C6551774559C084L);
        byte[] actualProduct = UMac.mult64(a, a);
        Assertions.assertArrayEquals(expectedProduct, actualProduct);
    }

    @Test
    public void testZeropad() {
        byte[] unpadded = {(byte) 0xDE, (byte) 0xEA, (byte) 0xC0, (byte) 0xDE};
        byte[] expectedPadded = {
            (byte) 0xDE, (byte) 0xEA, (byte) 0xC0, (byte) 0xDE, 0x00, 0x00, 0x00, 0x00
        };
        byte[] actualPadded = UMac.zeropad(unpadded, 8);
        Assertions.assertArrayEquals(expectedPadded, actualPadded);
    }
}
