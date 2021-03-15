/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.protocol;

import java.util.Arrays;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class AlgorithmPickerTest {

    public AlgorithmPickerTest() {
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
     * Test of pickAlgorithm method, of class AlgorithmPicker.
     */
    @Test
    public void testIdentity() {
        List<String> left = Arrays.asList("curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1", "ext-info-c"
        );
        String picked = AlgorithmPicker.pickAlgorithm(left, left).get();
        assertEquals(left.get(0), picked);
    }

    @Test
    public void testNoMatch() {
        List<String> left = Arrays.asList("curve25519-sha256");
        List<String> right = Arrays.asList("ecdh-sha2-nistp256");

        String picked = AlgorithmPicker.pickAlgorithm(left, right).orElse("");
        assertEquals("", picked);
    }

}
