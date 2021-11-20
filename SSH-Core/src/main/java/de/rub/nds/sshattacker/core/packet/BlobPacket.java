/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.packet.preparator.BlobPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.BlobPacketSerializer;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class BlobPacket extends AbstractPacket {
    @Override
    public BlobPacketPreparator getPacketPreparator(
            Chooser chooser, AbstractPacketEncryptor encryptor) {
        return new BlobPacketPreparator(chooser, this, encryptor);
    }

    @Override
    public BlobPacketParser getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher) {
        return new BlobPacketParser(array, startPosition);
    }

    @Override
    public BlobPacketSerializer getPacketSerializer() {
        return new BlobPacketSerializer(this);
    }

    @Override
    public void prepareComputations() {}
}
