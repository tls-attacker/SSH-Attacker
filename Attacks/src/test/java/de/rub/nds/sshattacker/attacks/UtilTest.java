package de.rub.nds.sshattacker.attacks;

import de.rub.nds.sshattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class UtilTest {

    @Test
    public void testMgf1() {
        String input = "bar";
        String output = "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1";
        try {
            byte[] maskBytes = Pkcs1VectorGenerator.mgf1(input.getBytes(StandardCharsets.UTF_8),
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
    public void testOaep() {
        byte[] message = new byte[1];
        message[0] = (byte) 42;
        try {
            byte[] bytes = Pkcs1VectorGenerator.doOaepEncoding(message, "SHA-256",  256);
            byte[] result = Pkcs1VectorGenerator.doOaepDecoding(bytes, "SHA-256",  256);
            assertArrayEquals(message, result);
        } catch (NoSuchAlgorithmException e) {
            fail("Test failed because hash alg does not exist.");
        }
    }

}