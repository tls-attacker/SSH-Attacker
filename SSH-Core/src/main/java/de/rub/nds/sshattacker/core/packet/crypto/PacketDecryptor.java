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
import de.rub.nds.sshattacker.core.exceptions.DecryptionException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketDecryptor extends AbstractPacketDecryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;

    public PacketDecryptor(PacketCipher packetCipher, SshContext context) {
        super(packetCipher);
        if (packetCipher.getMode() != CipherMode.DECRYPT) {
            throw new IllegalArgumentException(
                    "A PacketCipher provided to the PacketDecryptor constructor must be in DECRYPT mode");
        }
        this.context = context;
    }

    @Override
    public void decrypt(BinaryPacket packet) throws DecryptionException {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Decrypting binary packet using packet cipher: {}", packetCipher);
        try {
            packet.setSequenceNumber(context.getReadSequenceNumber());
            packetCipher.process(packet);
        } catch (CryptoException ex) {
            throw new DecryptionException(
                    "Could not decrypt binary packet using " + packetCipher, ex);
        }
        context.incrementReadSequenceNumber();
    }

    @Override
    public void decrypt(BlobPacket packet) throws DecryptionException {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Decrypting blob packet using packet cipher: {}", packetCipher);
        try {
            packetCipher.process(packet);
        } catch (CryptoException ex) {
            throw new DecryptionException(
                    "Could not decrypt blob packet using " + packetCipher, ex);
        }
    }

    @Override
    public void addNewPacketCipher(PacketCipher packetCipher) {
        if (packetCipher.getMode() != CipherMode.DECRYPT) {
            throw new IllegalArgumentException(
                    "A PacketCipher provided to the PacketDecryptor::addNewPacketCipher method must be in DECRYPT mode");
        }
        super.addNewPacketCipher(packetCipher);
    }
}
