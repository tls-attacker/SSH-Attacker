/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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

public abstract class AbstractPacketEncryptor extends PacketCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    public AbstractPacketEncryptor(PacketCipher cipher) {
        super(cipher);
    }

    public void encrypt(AbstractPacket object) {
        if (object instanceof BinaryPacket) {
            encrypt((BinaryPacket) object);
        } else if (object instanceof BlobPacket) {
            encrypt((BlobPacket) object);
        } else {
            throw new UnsupportedOperationException("Record type unknown.");
        }
    }

    public abstract void encrypt(BinaryPacket object);

    public abstract void encrypt(BlobPacket object);
}
