/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.crypto;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketDecryptor extends AbstractPacketDecryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;
    private final PacketCipher noneCipher;

    public PacketDecryptor(PacketCipher packetCipher, SshContext context) {
        super(packetCipher);
        this.context = context;
        noneCipher = PacketCipherFactory.getNoneCipher(context);
    }

    @Override
    public void decrypt(BinaryPacket packet) {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Decrypting binary packet using packet cipher: {}", packetCipher);
        try {
            packet.setSequenceNumber(context.getReadSequenceNumber());
            packetCipher.decrypt(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Could not decrypt binary packet. Using " + noneCipher, e);
            try {
                noneCipher.decrypt(packet);
            } catch (CryptoException ex) {
                LOGGER.error("Could not decrypt with " + noneCipher, ex);
            }
        }
        context.incrementReadSequenceNumber();
    }

    @Override
    public void decrypt(BlobPacket packet) {
        PacketCipher packetCipher = getPacketMostRecentCipher();
        LOGGER.debug("Decrypting blob packet using packet cipher: {}", packetCipher);
        try {
            packetCipher.decrypt(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Could not decrypt blob packet. Using " + noneCipher, e);
            try {
                noneCipher.decrypt(packet);
            } catch (CryptoException ex) {
                LOGGER.error("Could not decrypt with " + noneCipher, ex);
            }
        }
    }
}
