package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import java.util.Arrays;
import java.util.Collection;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHKeyExchangeReplyMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][]{
            {
                ArrayConverter.hexStringToByteArray("000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e065410000002020b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905000000630000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856"),
                104,
                0x13,
                "ecdsa-sha2-nistp256",
                8,
                "nistp256",
                65,
                ArrayConverter.hexStringToByteArray("0435496f94112c3234092471322c26dd21ebfd2da156e5a17dcc5dc98020afedd64ae82e5d4c28251187a2191fe85ae43de9734711c087b784eaa713d5b6e06541"),
                32,
                ArrayConverter.hexStringToByteArray("20b9f89aba2d7da23775b3ce085ff65f4d4b7ccf51ce2d073ef9158d6df1e905"),
                99,
                ArrayConverter.hexStringToByteArray("0000001365636473612d736861322d6e6973747032353600000048000000204e553a825dd144d7ddbd38cbd10a153a8a4ad597bf8da7ef1fe2546c851d6e89000000205bc4705cdac12213822e61c3b48ab7c84489ef3be0bb94ef524a45664b473856")
            },});
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

    public ECDHKeyExchangeReplyMessageParserTest(byte[] bytes, int hostKeyLength,
            int hostKeyTypeLength, String hostKeyType, int eccCurveIdentifierLength,
            String eccCurveIdentifier, int eccHostKeyLength, byte[] eccHostKey, 
            int publicKeyLength, byte[] publicKey, int signatureLength, byte[] signature) {
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
     * Test of parse method, of class ECDHKeyExchangeReplyMessageParser.
     */
    @Test
    public void testParseMessageSpecificPayload() {
        ECDHKeyExchangeReplyMessageParser parser = new ECDHKeyExchangeReplyMessageParser(0, bytes);
        ECDHKeyExchangeReplyMessage msg = new ECDHKeyExchangeReplyMessage();
        parser.parseMessageSpecificPayload(msg);
        assertEquals(hostKeyLength, msg.getHostKeyLength().getValue().intValue());
        assertEquals(hostKeyTypeLength, msg.getHostKeyTypeLength().getValue().intValue());
        assertEquals(hostKeyType, msg.getHostKeyType().getValue());

        assertEquals(eccCurveIdentifierLength, msg.getEccCurveIdentifierLength().getValue().intValue());
        assertEquals(eccCurveIdentifier, msg.getEccCurveIdentifier().getValue());
        assertEquals(eccHostKeyLength, msg.getHostKeyEccLength().getValue().intValue());
        Assert.assertArrayEquals(eccHostKey, msg.getHostKeyEcc().getValue());
        
        assertEquals(publicKeyLength, msg.getEphemeralPublicKeyLength().getValue().intValue());
        assertArrayEquals(publicKey, msg.getEphemeralPublicKey().getValue());
        assertEquals(signatureLength, msg.getSignatureLength().getValue().intValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }
}
