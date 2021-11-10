/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.packet;

import de.rub.nds.sshattacker.core.crypto.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.crypto.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.crypto.packet.cipher.PacketNoneCipher;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.packet.BlobPacket;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketEncryptor extends AbstractPacketEncryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;
    private final PacketNoneCipher noneCipher;

    public PacketEncryptor(PacketCipher packetCipher, SshContext context) {
        super(packetCipher);
        this.context = context;
        noneCipher = PacketCipherFactory.getNoneCipher(context);
    }

    @Override
    public void encrypt(BinaryPacket packet) {
        LOGGER.debug("Encrypting binary packet");
        PacketCipher packetCipher = getPacketMostRecentCipher();
        try {
            packet.setSequenceNumber(context.getWriteSequenceNumber());
            packetCipher.encrypt(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Could not encrypt binary packet. Using NoneCipher", e);
            try {
                noneCipher.encrypt(packet);
            } catch (CryptoException ex) {
                LOGGER.error("Could not encrypt with NoneCipher", ex);
            }
        }
        context.incrementWriteSequenceNumber();
    }

    @Override
    public void encrypt(BlobPacket object) {
        // TODO: Implement encryption of blob packets
        LOGGER.debug("Encryption of blob packets not implemented - not doing anything");
    }
}
