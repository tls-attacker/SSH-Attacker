package de.rub.nds.sshattacker.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
    
}
