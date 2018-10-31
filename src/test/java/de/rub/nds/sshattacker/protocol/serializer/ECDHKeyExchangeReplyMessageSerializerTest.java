package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.protocol.parser.ECDHKeyExchangeReplyMessageParserTest;
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
public class ECDHKeyExchangeReplyMessageSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHKeyExchangeReplyMessageParserTest.generateData();
    }

    private final byte[] bytes;

    private final int hostKeyLength;

    private final int hostKeyTypeLength;
    private final String hostKeyType;

    private final int exponentLength;
    private final byte[] exponent;

    private final int modulusLength;
    private final byte[] modulus;

    private final int publicKeyLength;
    private final byte[] publicKey;

    private final int signatureLength;
    private final byte[] signature;

    public ECDHKeyExchangeReplyMessageSerializerTest(byte[] bytes, int hostKeyLength, int hostKeyTypeLength, String hostKeyType, int exponentLength, byte[] exponent, int modulusLength, byte[] modulus, int publicKeyLength, byte[] publicKey, int signatureLength, byte[] signature) {
        this.bytes = bytes;
        this.hostKeyLength = hostKeyLength;
        this.hostKeyTypeLength = hostKeyTypeLength;
        this.hostKeyType = hostKeyType;
        this.exponentLength = exponentLength;
        this.exponent = exponent;
        this.modulusLength = modulusLength;
        this.modulus = modulus;
        this.publicKeyLength = publicKeyLength;
        this.publicKey = publicKey;
        this.signatureLength = signatureLength;
        this.signature = signature;
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
     * ECDHKeyExchangeReplyMessageSerializer.
     */
    @Test
    public void testSerializeMessageSpecificPayload() {
        ECDHKeyExchangeReplyMessage msg = new ECDHKeyExchangeReplyMessage();
        msg.setHostKeyLength(hostKeyLength);
        msg.setHostKeyTypeLength(hostKeyTypeLength);
        msg.setHostKeyType(hostKeyType);
        msg.setExponentLength(exponentLength);
        msg.setExponent(exponent);
        msg.setModulusLength(modulusLength);
        msg.setModulus(modulus);
        msg.setPublicKeyLength(publicKeyLength);
        msg.setPublicKey(publicKey);
        msg.setSignatureLength(signatureLength);
        msg.setSignature(signature);

        ECDHKeyExchangeReplyMessageSerializer serializer = new ECDHKeyExchangeReplyMessageSerializer(msg);

        assertArrayEquals(bytes, serializer.serializeMessageSpecificPayload());
    }

}
