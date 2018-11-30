package de.rub.nds.sshattacker.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.util.Converter;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class KeyDerivationTest {
    
    public KeyDerivationTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of DheX25519 method, of class KeyDerivation.
     */
    @Test
    public void testDheX25519() {
        byte[] clientPrivateKey = ArrayConverter.hexStringToByteArray("90bfc2074ca9e89a54d870afafd2edc22f4523e1343e2eceaf4af0fad5837625");
        byte[] serverPublicKey = ArrayConverter.hexStringToByteArray("2c6e16b6cc87c4ba691c4d1d9881ffe5dda32ae7b78e9aa905e88546c2fa442b");
        byte[] expectedSharedSecret = ArrayConverter.hexStringToByteArray("f01590a6dbe06a5f69a0ed95a4352f7ecd38eb2e1d82dfd5bda828007e6de112");
        
        byte[] sharedSecret = KeyDerivation.DheX25519(clientPrivateKey, serverPublicKey);
        
        assertArrayEquals(expectedSharedSecret, sharedSecret);
    }
    
    @Test
    public void testDeriveKey(){
        byte[] sharedSecret = Converter.byteArraytoMpint(ArrayConverter.hexStringToByteArray("f01590a6dbe06a5f69a0ed95a4352f7ecd38eb2e1d82dfd5bda828007e6de112"));
        byte[] exchangeHash = ArrayConverter.hexStringToByteArray("bc2e0234e4feefa2835970b462dbdcecdf92deed61010155796cb749261da902");
        byte[] expectedKeyA = ArrayConverter.hexStringToByteArray("22a8b14ea027a35fa5da85390324b521d35d493cfb374879abcf03b92f1efec7578f27de759d6be0de4b573aee94ccfed00d6ae1538af0dc8ecc3a6a6ef99557");
        byte[] expectedKeyB = ArrayConverter.hexStringToByteArray("3f33224b08c8cf18ec4cee2e5ede0c03f23c11a4cb8d7445d53ed55ee9f5354184d60fc67840f815bcd8a48ff92aa358bd7736ad734f7123c50867f91cd2595d");
        byte[] expectedKeyC = ArrayConverter.hexStringToByteArray("d39824b7fff07ca4ebad1f06ce300983b52f28b72359371e42d008aad0960708c5e421aba1c9f13731d25cd4faf10b43fb48d36bfb7fc1d8d32f6120529d13f8");
        byte[] expectedKeyD = ArrayConverter.hexStringToByteArray("6c64c65b39b4d87bf5e8c799009618c23c6edbc065e37af712e80e231da943f4d99072dacf310f4885bef0189d5a016aeb406798eb4d514d75afabce8dce99b0");
        byte[] expectedKeyE = ArrayConverter.hexStringToByteArray("c87e9104796e2359a677895e2ac9e1f371220ff8e49346cd9b1666f22de1f03e0905679661a682cd6d10976e44f38fff489da3e0b85f53dc27cd8de90837ef8c");
        byte[] expectedKeyF = ArrayConverter.hexStringToByteArray("8dd26c678a145f99716eefe92edd46439b81197e2cad71defdc7f02c8c4046c265a9d0775c9f2d0ee90e1359a144c30c1db8bccd1575de5458b8a19ad14d7d53");
        
        byte[] keyA = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'A', exchangeHash, expectedKeyA.length, "SHA-256");
        byte[] keyB = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'B', exchangeHash, expectedKeyB.length, "SHA-256");
        byte[] keyC = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'C', exchangeHash, expectedKeyC.length, "SHA-256");
        byte[] keyD = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'D', exchangeHash, expectedKeyD.length, "SHA-256");
        byte[] keyE = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'E', exchangeHash, expectedKeyE.length, "SHA-256");
        byte[] keyF = KeyDerivation.deriveKey(sharedSecret, exchangeHash, (byte) 'F', exchangeHash, expectedKeyF.length, "SHA-256");
        
        assertArrayEquals(expectedKeyA, keyA);
        assertArrayEquals(expectedKeyB, keyB);
        assertArrayEquals(expectedKeyC, keyC);
        assertArrayEquals(expectedKeyD, keyD);
        assertArrayEquals(expectedKeyE, keyE);
        assertArrayEquals(expectedKeyF, keyF);
    }
    
}
