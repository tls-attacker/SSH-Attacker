/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.crypto;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractPacketDecryptor extends PacketCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    public AbstractPacketDecryptor(PacketCipher cipher) {
        super(cipher);
    }

    public void decrypt(AbstractPacket object) {
        if (object instanceof BinaryPacket) {
            decrypt((BinaryPacket) object);
        } else if (object instanceof BlobPacket) {
            decrypt((BlobPacket) object);
        } else {
            throw new UnsupportedOperationException("Packet type unknown.");
        }
    }

    public abstract void decrypt(BinaryPacket object);

    public abstract void decrypt(BlobPacket object);
}
