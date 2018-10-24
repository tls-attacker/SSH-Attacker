package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.parser.ECDHKeyExchangeInitMessageParserTest;
import java.util.Collection;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHKeyExchangeInitMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHKeyExchangeInitMessageParserTest.generateData();
    }

    private final byte[] bytes;

    private final int publicKeyLength;
    private final byte[] publicKey;

    public ECDHKeyExchangeInitMessageSerializerTest(byte[] bytes, int publicKeyLength, byte[] publicKey) {
        this.bytes = bytes;
        this.publicKeyLength = publicKeyLength;
        this.publicKey = publicKey;
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
     * Test of serializeBytes method, of class
     * ECDHKeyExchangeInitMessageSerializer.
     */
    @Test
    public void testSerializeBytes() {
        ECDHKeyExchangeInitMessage msg = new ECDHKeyExchangeInitMessage();
        msg.setPublicKeyLength(publicKeyLength);
        msg.setPublicKey(publicKey);

        ECDHKeyExchangeInitMessageSerializer serializer = new ECDHKeyExchangeInitMessageSerializer(msg);

        assertArrayEquals(bytes, serializer.serialize());
    }

}
