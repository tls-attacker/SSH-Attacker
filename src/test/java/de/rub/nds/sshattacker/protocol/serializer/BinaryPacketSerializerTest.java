package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.parser.BinaryPacketParserTest;
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
public class BinaryPacketSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return BinaryPacketParserTest.generateData();
    }
    
    private final int packetLength;
    private final byte paddingLength;
    private final byte[] payload;
    private final byte[] padding;
    private final byte[] mac;
    
    private final byte[] bytes;
    
    public BinaryPacketSerializerTest(byte[] bytes, int packetLength, byte paddingLength, byte[] payload, byte[] padding, byte[] mac) {
        this.bytes = bytes;
        this.packetLength = packetLength;
        this.paddingLength = paddingLength;
        this.payload = payload;
        this.padding = padding;
        this.mac = mac;
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
     * Test of serializeBytes method, of class BinaryPacketSerializer.
     */
    @Test
    public void testSerializeBytes() {
        BinaryPacket msg = new BinaryPacket();
        msg.setPacketLength(packetLength);
        msg.setPaddingLength(paddingLength);
        msg.setPayload(payload);
        msg.setPadding(padding);
        msg.setMac(mac);
        BinaryPacketSerializer serializer = new BinaryPacketSerializer(msg);
        assertArrayEquals(bytes, serializer.serialize());
    }
    
}
