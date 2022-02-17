package de.rub.nds.sshattacker.attacks.pkcs1.util;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class OaepConverterTest {

    @Test
    public void xorTest() {
        byte[] leftInput = new byte[2];
        leftInput[0] = (byte) 17;
        leftInput[1] = (byte) 1;
        byte[] rightInput = new byte[2];
        rightInput[0] = (byte) 22;
        rightInput[1] = (byte) 42;
        byte[] expectedOutput = new byte[2];
        expectedOutput[0] = (byte) 7;
        expectedOutput[1] = (byte) 43;

        assertArrayEquals(expectedOutput, OaepConverter.xor(leftInput, rightInput));

    }

    @Test
    public void mgf1Test() {
        String input = "bar";
        String output = "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1";
        try {
            byte[] maskBytes = OaepConverter.mgf1(input.getBytes(StandardCharsets.UTF_8),
                    50,
                    "SHA-256"
                    );
            String maskedBytesInHex = new BigInteger(maskBytes).toString(16);
            assertEquals(output, maskedBytesInHex);
        } catch (NoSuchAlgorithmException e) {
            fail("Test failed because hash alg does not exist.");
        }
    }

    @Test
    public void oaepTest() {
        byte[] message = new byte[1];
        message[0] = (byte) 42;
        try {
            byte[] bytes = OaepConverter.doOaepEncoding(message, "SHA-256",  256);
            byte[] result = OaepConverter.doOaepDecoding(bytes, "SHA-256",  256);
            assertArrayEquals(message, result);
        } catch (NoSuchAlgorithmException e) {
            fail("Test failed because hash alg does not exist.");
        }
    }

}