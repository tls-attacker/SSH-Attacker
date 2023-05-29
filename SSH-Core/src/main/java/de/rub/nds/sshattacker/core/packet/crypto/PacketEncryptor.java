/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.crypto;

import de.rub.nds.sshattacker.core.constants.CipherMode;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketEncryptor extends AbstractPacketEncryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;
    private final PacketCipher noneCipher;

    public PacketEncryptor(PacketCipher packetCipher, SshContext context) {
        super(packetCipher);
        if (packetCipher.getMode() != CipherMode.ENCRYPT) {
            throw new IllegalArgumentException(
                    "A PacketCipher provided to the PacketEncryptor constructor must be in ENCRYPT mode");
        }
        this.context = context;
        noneCipher = PacketCipherFactory.getNoneCipher(context, CipherMode.ENCRYPT);
    }

    @Override
    public void encrypt(BinaryPacket packet) {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Encrypting binary packet using packet cipher: {}", packetCipher);
        try {
            packet.setSequenceNumber(context.getWriteSequenceNumber());
            packetCipher.process(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Could not encrypt binary packet. Using " + noneCipher, e);
            try {
                noneCipher.process(packet);
            } catch (CryptoException ex) {
                LOGGER.error("Could not encrypt with " + noneCipher, ex);
            }
        }
        context.incrementWriteSequenceNumber();
    }

    @Override
    public void encrypt(BlobPacket packet) {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Encrypting blob packet using packet cipher: {}", packetCipher);
        try {
            packetCipher.process(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Could not encrypt blob packet. Using " + noneCipher, e);
            try {
                noneCipher.process(packet);
            } catch (CryptoException ex) {
                LOGGER.error("Could not encrypt with " + noneCipher, ex);
            }
        }
    }

    @Override
    public void addNewPacketCipher(PacketCipher packetCipher) {
        if (packetCipher.getMode() != CipherMode.ENCRYPT) {
            throw new IllegalArgumentException(
                    "A PacketCipher provided to the PacketDecryptor::addNewPacketCipher method must be in ENCRYPT mode");
        }
        super.addNewPacketCipher(packetCipher);
    }
}
