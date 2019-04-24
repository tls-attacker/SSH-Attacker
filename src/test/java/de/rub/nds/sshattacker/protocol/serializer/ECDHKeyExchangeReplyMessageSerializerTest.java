package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeReplyMessage;
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

    private final int eccCurveIdentifierLength;
    private final String eccCurveIdentifier;

    private final int eccHostKeyLength;
    private final byte[] eccHostKey;

    private final int publicKeyLength;
    private final byte[] publicKey;

    private final int signatureLength;
    private final byte[] signature;

    public ECDHKeyExchangeReplyMessageSerializerTest(byte[] bytes, int hostKeyLength, int hostKeyTypeLength, String hostKeyType, int eccCurveIdentifierLength, String eccCurveIdentifier, int eccHostKeyLength, byte[] eccHostKey, int publicKeyLength, byte[] publicKey, int signatureLength, byte[] signature) {
        this.bytes = bytes;
        this.hostKeyLength = hostKeyLength;
        this.hostKeyTypeLength = hostKeyTypeLength;
        this.hostKeyType = hostKeyType;
        this.eccCurveIdentifierLength = eccCurveIdentifierLength;
        this.eccCurveIdentifier = eccCurveIdentifier;
        this.eccHostKeyLength = eccHostKeyLength;
        this.eccHostKey = eccHostKey;
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
 EcdhKeyExchangeReplyMessageSerializer.
     */
    @Test
    public void testSerializeMessageSpecificPayload() {
        EcdhKeyExchangeReplyMessage msg = new EcdhKeyExchangeReplyMessage();
        msg.setHostKeyLength(hostKeyLength);
        msg.setHostKeyTypeLength(hostKeyTypeLength);
        msg.setHostKeyType(hostKeyType);
        msg.setEccCurveIdentifierLength(eccCurveIdentifierLength);
        msg.setEccCurveIdentifier(eccCurveIdentifier);
        msg.setHostKeyEccLength(eccHostKeyLength);
        msg.setHostKeyEcc(eccHostKey);
        msg.setPublicKeyLength(publicKeyLength);
        msg.setPublicKey(publicKey);
        msg.setSignatureLength(signatureLength);
        msg.setSignature(signature);

        EcdhKeyExchangeReplyMessageSerializer serializer = new EcdhKeyExchangeReplyMessageSerializer(msg);

        assertArrayEquals(bytes, serializer.serializeMessageSpecificPayload());
    }

}
