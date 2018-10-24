package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import java.util.Arrays;
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
public class ECDHKeyExchangeReplyMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][]{
            {
                ArrayConverter.hexStringToByteArray("00000115000000077373682d72736100000001230000010100ab603b8511a67679bdb540db3bd2034b004ae936d06be3d760f08fcbaadb4eb4edc3b3c791c70aae9a74c95869e4774421c2abea92e554305f38b5fd414b3208e574c337e320936518462c7652c98b31e16e7da6523bd200742a6444d83fcd5e1732d03673c7b7811555487b55f0c4494f3829ece60f94255a95cb9af537d7fc8c7fe49ef318474ef2920992052265b0a06ea66d4a167fd9f3a48a1a4a307ec1eaaa5149a969a6ac5d56a5ef627e517d81fb644f5b745c4f478ecd082a9492f744aad326f76c8c4dc9100bc6ab79461d2657cb6f06dec92e6b64a6562ff0e32084ea06ce0ea9d35a583bfb00bad38c9d19703c549892e5aa78dc95e250514069000000201c79ad1bb2ac0016492475c7d3807847e9827b640565c170732d001e164148430000010f000000077373682d727361000001005e06b4b5f5b1a267aa567d7e424b7e01ef2f6a1c3a1f7e1389cc8c1b195915383d745eb9b70cd3d63377c436124332e60b804410f7363d7fdcf2af1a97c2f5b78962eeb64b5c12bf384f930c5bf974d7e38ed86cd54cc63145e01b6ecebd0f7ef0ea19de2950bffc3a38843d3d6efe1e8e72e95a4d94f27af01d84fc15da0649b4853286cd7fc107bdd6c0d08fa75200fb38b5be9403185758f1f5b0a9cae8ff5f689d9d56c5bd34d83bfd5c7b9015aed7c3e70ea97ba9c0e1fb2b91780f96a3a3d2f789c39cd54149b3ca19f8694826bd37e0af153042ca7e217f0f4e79fb6e248624273c40f222f2d72a5469305a135bf1c0da0f2adfb37486740ffbc51365"),
                277,
                7,
                "ssh-rsa",
                0x1,
                new byte[]{0x23},
                257,
                ArrayConverter.hexStringToByteArray("00ab603b8511a67679bdb540db3bd2034b004ae936d06be3d760f08fcbaadb4eb4edc3b3c791c70aae9a74c95869e4774421c2abea92e554305f38b5fd414b3208e574c337e320936518462c7652c98b31e16e7da6523bd200742a6444d83fcd5e1732d03673c7b7811555487b55f0c4494f3829ece60f94255a95cb9af537d7fc8c7fe49ef318474ef2920992052265b0a06ea66d4a167fd9f3a48a1a4a307ec1eaaa5149a969a6ac5d56a5ef627e517d81fb644f5b745c4f478ecd082a9492f744aad326f76c8c4dc9100bc6ab79461d2657cb6f06dec92e6b64a6562ff0e32084ea06ce0ea9d35a583bfb00bad38c9d19703c549892e5aa78dc95e250514069"),
                32,
                ArrayConverter.hexStringToByteArray("1c79ad1bb2ac0016492475c7d3807847e9827b640565c170732d001e16414843"),
                271,
                ArrayConverter.hexStringToByteArray("000000077373682d727361000001005e06b4b5f5b1a267aa567d7e424b7e01ef2f6a1c3a1f7e1389cc8c1b195915383d745eb9b70cd3d63377c436124332e60b804410f7363d7fdcf2af1a97c2f5b78962eeb64b5c12bf384f930c5bf974d7e38ed86cd54cc63145e01b6ecebd0f7ef0ea19de2950bffc3a38843d3d6efe1e8e72e95a4d94f27af01d84fc15da0649b4853286cd7fc107bdd6c0d08fa75200fb38b5be9403185758f1f5b0a9cae8ff5f689d9d56c5bd34d83bfd5c7b9015aed7c3e70ea97ba9c0e1fb2b91780f96a3a3d2f789c39cd54149b3ca19f8694826bd37e0af153042ca7e217f0f4e79fb6e248624273c40f222f2d72a5469305a135bf1c0da0f2adfb37486740ffbc51365")
            },});
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

    public ECDHKeyExchangeReplyMessageParserTest(byte[] bytes, int hostKeyLength, int hostKeyTypeLength, String hostKeyType, int exponentLength, byte[] exponent, int modulusLength, byte[] modulus, int publicKeyLength, byte[] publicKey, int signatureLength, byte[] signature) {
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
     * Test of parse method, of class ECDHKeyExchangeReplyMessageParser.
     */
    @Test
    public void testParse() {
        ECDHKeyExchangeReplyMessageParser parser = new ECDHKeyExchangeReplyMessageParser(0, bytes);
        ECDHKeyExchangeReplyMessage msg = parser.parse();
        assertEquals(hostKeyLength, msg.getHostKeyLength().getValue().intValue());
        assertEquals(hostKeyTypeLength, msg.getHostKeyTypeLength().getValue().intValue());
        assertEquals(hostKeyType, msg.getHostKeyType().getValue());
        assertEquals(exponentLength, msg.getExponentLength().getValue().intValue());
        assertArrayEquals(exponent, msg.getExponent().getValue());
        assertEquals(modulusLength, msg.getModulusLength().getValue().intValue());
        assertArrayEquals(modulus, msg.getModulus().getValue());
        assertEquals(publicKeyLength, msg.getPublicKeyLength().getValue().intValue());
        assertArrayEquals(publicKey, msg.getPublicKey().getValue());
        assertEquals(signatureLength, msg.getSignatureLength().getValue().intValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }
}
