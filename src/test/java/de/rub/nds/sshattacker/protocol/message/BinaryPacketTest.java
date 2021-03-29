/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
    @SuppressWarnings({ "FieldCanBeLocal", "unused" })
    private int packetLength_5;

    public BinaryPacketTest() {
    }

    @Before
    public void setUp() {
        byte[] payload = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        paddingLength_8 = 9;
        paddingLength_5 = 9;
        packetLength_8 = payload.length + paddingLength_8 + BinaryPacketConstants.PADDING_FIELD_LENGTH;
        packetLength_5 = payload.length + paddingLength_5 + BinaryPacketConstants.PADDING_FIELD_LENGTH;
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
        assertEquals(packetLength_8, binaryPacket.getPacketLength().getValue().intValue());
    }

    /**
     * Test of computePaddingLength method, of class BinaryPacket.
     */
    @Test
    public void testComputePaddingLength_8() {
        binaryPacket.computePaddingLength((byte) BinaryPacketConstants.DEFAULT_BLOCK_SIZE);
        assertEquals(paddingLength_8, binaryPacket.getPaddingLength().getValue().intValue());
    }

    /**
     * Test of computePaddingLength method, of class BinaryPacket.
     */
    @Test
    public void testComputePaddingLength_byte() {
        binaryPacket.computePaddingLength((byte) 5);
        assertEquals(paddingLength_5, binaryPacket.getPaddingLength().getValue().intValue());
    }
}
