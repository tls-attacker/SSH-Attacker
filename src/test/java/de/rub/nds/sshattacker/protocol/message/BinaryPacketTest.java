package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class BinaryPacketTest {

    private BinaryPacket binaryPacket;
    private int paddingLength_8;
    private int paddingLength_5;
    private int packetLength_8;
    private int packetLength_5;

    public BinaryPacketTest() {
    }

    @Before
    public void setUp() {
        byte[] payload = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        paddingLength_8 = 1;
        paddingLength_5 = 0;
        packetLength_8 = payload.length + paddingLength_8 + 1;
        packetLength_5 = payload.length + paddingLength_5 + 1;
        binaryPacket = new BinaryPacket(ModifiableVariableFactory.safelySetValue(null, payload));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of computeLength method, of class BinaryPacket.
     */
    @Test
    public void testComputePacketLength() {
        binaryPacket.computePaddingLength((byte) BinaryPacketConstants.DEFAULT_BLOCK_SIZE);
        binaryPacket.computePacketLength();
        assertTrue(binaryPacket.getPacketLength().getValue() == packetLength_8);
    }

    /**
     * Test of computePaddingLength method, of class BinaryPacket.
     */
    @Test
    public void testComputePaddingLength_8() {
        binaryPacket.computePaddingLength((byte) BinaryPacketConstants.DEFAULT_BLOCK_SIZE);
        assertTrue(binaryPacket.getPaddingLength().getValue() == paddingLength_8);
    }

    /**
     * Test of computePaddingLength method, of class BinaryPacket.
     */
    @Test
    public void testComputePaddingLength_byte() {
        binaryPacket.computePaddingLength((byte) 5);
        assertTrue(binaryPacket.getPaddingLength().getValue() == paddingLength_5);
    }
}
