/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.packet.preparator.BlobPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.BlobPacketSerializer;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class BlobPacket extends AbstractPacket {

    public BlobPacket() {
        super();
    }

    public BlobPacket(BlobPacket other) {
        super(other);
    }

    @Override
    public BlobPacket createCopy() {
        return new BlobPacket(this);
    }

    @Override
    public BlobPacketParser getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher, int sequenceNumber) {
        return new BlobPacketParser(array, startPosition);
    }

    public static final BlobPacketPreparator PREPARATOR = new BlobPacketPreparator();

    public void prepare(Chooser chooser) {
        PREPARATOR.prepare(this, chooser);
    }

    @Override
    public BlobPacketSerializer getPacketSerializer() {
        return new BlobPacketSerializer(this);
    }

    @Override
    public void prepareComputations() {}
}
