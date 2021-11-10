/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.packet.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Collections;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketNoneCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public PacketNoneCipher(
            SshContext context,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm) {
        super(context, null, encryptionAlgorithm, macAlgorithm);
    }

    @Override
    public void encrypt(BinaryPacket packet) throws CryptoException {
        LOGGER.debug("Encrypting binary packet using cipher: (none cipher)");
        packet.prepareComputations();
        PacketCryptoComputations computations = packet.getComputations();
        // Encryption (empty byte arrays)
        computations.setEncryptedPacketFields(Collections.emptySet());
        computations.setPlainPacketBytes(new byte[0]);
        computations.setCiphertext(new byte[0]);
        // Padding
        computations.setPaddingLength(calculatePaddingLength(packet));
        computations.setPadding(calculatePadding(computations.getPaddingLength().getValue()));
        // Packet length field
        packet.setLength(calculatePacketLength(packet));
        // Integrity protection (empty byte arrays)
        computations.setAuthenticatedPacketBytes(new byte[0]);
        computations.setMac(new byte[0]);
        computations.setMacValid(true);
        computations.setPaddingValid(true);
    }

    @Override
    public void decrypt(BinaryPacket packet) throws CryptoException {
        LOGGER.debug("Decrypting binary packets using cipher: (none cipher)");
        packet.prepareComputations();
        PacketCryptoComputations computations = packet.getComputations();
        // Decryption (empty byte arrays)
        packet.getComputations().setEncryptedPacketFields(Collections.emptySet());
        packet.getComputations().setPlainPacketBytes(new byte[0]);
        packet.getComputations().setCiphertext(new byte[0]);
        // Padding (already set by the BinaryPacketParser)
        // Integrity protection (already set by the BinaryPacketParser)
        computations.setMacValid(computations.getMac().getValue().length == 0);
        computations.setPaddingValid(isPaddingValid(computations.getPadding().getValue()));
    }
}
