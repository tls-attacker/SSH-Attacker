package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
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
public class KeyExchangeInitMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][]{
            {
                ArrayConverter.hexStringToByteArray("e0b018941e57551ede3fde36a71e08080000007a637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235360000000f7373682d6473732c7373682d7273610000005f63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d6374722c6165733139322d6374722c6165733132382d6374722c6165733235362d6362632c6165733139322d6362632c6165733132382d6362630000005f63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d6374722c6165733139322d6374722c6165733132382d6374722c6165733235362d6362632c6165733139322d6362632c6165733132382d63626300000025686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d7368613100000025686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c69622c7a6c6962406f70656e7373682e636f6d0000001a6e6f6e652c7a6c69622c7a6c6962406f70656e7373682e636f6d00000000000000000000000000"),
                ArrayConverter.hexStringToByteArray("e0b018941e57551ede3fde36a71e0808"),
                122,
                "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256",
                15,
                "ssh-dss,ssh-rsa",
                95,
                "chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc",
                95,
                "chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc",
                37,
                "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                37,
                "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                26,
                "none,zlib,zlib@openssh.com",
                26,
                "none,zlib,zlib@openssh.com",
                0,
                "",
                0,
                "",
                (byte) 0,
                0x00000000
            },
            {
                ArrayConverter.hexStringToByteArray("fbf207980a5e1f64469ee7dad6593e070000010d637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d63000001667273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c696200000000000000000000000000"),
                ArrayConverter.hexStringToByteArray("fbf207980a5e1f64469ee7dad6593e07"),
                269,
                "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
                358,
                "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519",
                108,
                "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
                108,
                "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
                213,
                "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                213,
                "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                26,
                "none,zlib@openssh.com,zlib",
                26,
                "none,zlib@openssh.com,zlib",
                0,
                "",
                0,
                "",
                (byte) 0,
                0x00000000}
        });
    }

    private final byte[] bytes;

    private final byte[] cookie;
    private final int keyExchangeAlgorithmsLength;
    private final String keyExchangeAlgorithms;
    private final int serverHostKeyAlgorithmsLength;
    private final String serverHostKeyAlgorithms;
    private final int encryptionAlgorithmsClientToServerLength;
    private final String encryptionAlgorithmsClientToServer;
    private final int encryptionAlgorithmsServerToClientLength;
    private final String encryptionAlgorithmsServerToClient;
    private final int macAlgorithmsClientToServerLength;
    private final String macAlgorithmsClientToServer;
    private final int macAlgorithmsServerToClientLength;
    private final String macAlgorithmsServerToClient;
    private final int compressionAlgorithmsClientToServerLength;
    private final String compressionAlgorithmsClientToServer;
    private final int compressionAlgorithmsServerToClientLength;
    private final String compressionAlgorithmsServerToClient;
    private final int languagesClientToServerLength;
    private final String languagesClientToServer;
    private final int languagesServerToClientLength;
    private final String languagesServerToClient;
    private final byte firstKeyExchangePacketFollows;
    private final int reserved;

    public KeyExchangeInitMessageParserTest(byte[] bytes, byte[] cookie, int keyExchangeAlgorithmsLength, String keyExchangeAlgorithms, int serverHostKeyAlgorithmsLength, String serverHostKeyAlgorithms, int encryptionAlgorithmsClientToServerLength, String encryptionAlgorithmsClientToServer, int encryptionAlgorithmsServerToClientLength, String encryptionAlgorithmsServerToClient, int macAlgorithmsClientToServerLength, String macAlgorithmsClientToServer, int macAlgorithmsServerToClientLength, String macAlgorithmsServerToClient, int compressionAlgorithmsClientToServerLength, String compressionAlgorithmsClientToServer, int compressionAlgorithmsServerToClientLength, String compressionAlgorithmsServerToClient, int languagesClientToServerLength, String languagesClientToServer, int languagesServerToClientLength, String languagesServerToClient, byte firstKeyExchangePacketFollows, int reserved) {
        this.bytes = bytes;
        this.cookie = cookie;
        this.keyExchangeAlgorithmsLength = keyExchangeAlgorithmsLength;
        this.keyExchangeAlgorithms = keyExchangeAlgorithms;
        this.serverHostKeyAlgorithmsLength = serverHostKeyAlgorithmsLength;
        this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
        this.encryptionAlgorithmsClientToServerLength = encryptionAlgorithmsClientToServerLength;
        this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
        this.encryptionAlgorithmsServerToClientLength = encryptionAlgorithmsServerToClientLength;
        this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
        this.macAlgorithmsClientToServerLength = macAlgorithmsClientToServerLength;
        this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
        this.macAlgorithmsServerToClientLength = macAlgorithmsServerToClientLength;
        this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
        this.compressionAlgorithmsClientToServerLength = compressionAlgorithmsClientToServerLength;
        this.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer;
        this.compressionAlgorithmsServerToClientLength = compressionAlgorithmsServerToClientLength;
        this.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient;
        this.languagesClientToServerLength = languagesClientToServerLength;
        this.languagesClientToServer = languagesClientToServer;
        this.languagesServerToClientLength = languagesServerToClientLength;
        this.languagesServerToClient = languagesServerToClient;
        this.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows;
        this.reserved = reserved;
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
     * Test of parse method, of class KeyExchangeInitMessageParser.
     */
    @Test
    public void testParseMessageSpecificPayload() {
        KeyExchangeInitMessageParser parser = new KeyExchangeInitMessageParser(0, bytes);
        KeyExchangeInitMessage msg = new KeyExchangeInitMessage();
        parser.parseMessageSpecificPayload(msg);
        assertArrayEquals(cookie, msg.getCookie().getValue());
        assertEquals(keyExchangeAlgorithmsLength, msg.getKeyExchangeAlgorithmsLength().getValue().intValue());
        assertEquals(keyExchangeAlgorithms, msg.getKeyExchangeAlgorithms().getValue());
        assertEquals(serverHostKeyAlgorithmsLength, msg.getServerHostKeyAlgorithmsLength().getValue().intValue());
        assertEquals(serverHostKeyAlgorithms, msg.getServerHostKeyAlgorithms().getValue());
        assertEquals(encryptionAlgorithmsClientToServerLength, msg.getEncryptionAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(encryptionAlgorithmsClientToServer, msg.getEncryptionAlgorithmsClientToServer().getValue());
        assertEquals(encryptionAlgorithmsServerToClientLength, msg.getEncryptionAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(encryptionAlgorithmsServerToClient, msg.getEncryptionAlgorithmsServerToClient().getValue());
        assertEquals(macAlgorithmsClientToServerLength, msg.getMacAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(macAlgorithmsClientToServer, msg.getMacAlgorithmsClientToServer().getValue());
        assertEquals(macAlgorithmsServerToClientLength, msg.getMacAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(macAlgorithmsServerToClient, msg.getMacAlgorithmsServerToClient().getValue());
        assertEquals(compressionAlgorithmsClientToServerLength, msg.getCompressionAlgorithmsClientToServerLength().getValue().intValue());
        assertEquals(compressionAlgorithmsClientToServer, msg.getCompressionAlgorithmsClientToServer().getValue());
        assertEquals(compressionAlgorithmsServerToClientLength, msg.getCompressionAlgorithmsServerToClientLength().getValue().intValue());
        assertEquals(compressionAlgorithmsServerToClient, msg.getCompressionAlgorithmsServerToClient().getValue());
        assertEquals(languagesClientToServerLength, msg.getLanguagesClientToServerLength().getValue().intValue());
        assertEquals(languagesClientToServer, msg.getLanguagesClientToServer().getValue());
        assertEquals(languagesServerToClientLength, msg.getLanguagesServerToClientLength().getValue().intValue());
        assertEquals(languagesServerToClient, msg.getLanguagesServerToClient().getValue());
        assertEquals(firstKeyExchangePacketFollows, msg.getFirstKeyExchangePacketFollows().getValue().byteValue());
        assertEquals(reserved, msg.getReserved().getValue().intValue());
    }
}
