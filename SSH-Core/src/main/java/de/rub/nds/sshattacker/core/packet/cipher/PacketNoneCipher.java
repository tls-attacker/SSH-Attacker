/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
        packet.prepareComputations();
        PacketCryptoComputations computations = packet.getComputations();
        // Encryption (copy payload)
        computations.setEncryptedPacketFields(
                Stream.of(BinaryPacketField.PAYLOAD).collect(Collectors.toSet()));
        packet.setCiphertext(packet.getPayload().getValue());
        // Padding
        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(calculatePadding(packet.getPaddingLength().getValue()));
        // Packet length field
        packet.setLength(calculatePacketLength(packet));
        // Integrity protection (empty byte arrays)
        packet.setMac(new byte[0]);
        computations.setMacValid(true);
        computations.setPaddingValid(true);
    }

    @Override
    public void encrypt(BlobPacket packet) throws CryptoException {
        packet.setCiphertext(packet.getPayload().getValue());
    }

    @Override
    public void decrypt(BinaryPacket packet) throws CryptoException {
        packet.prepareComputations();
        PacketCryptoComputations computations = packet.getComputations();
        // Decryption (empty byte arrays)
        computations.setEncryptedPacketFields(
                Stream.of(BinaryPacketField.PAYLOAD).collect(Collectors.toSet()));
        packet.setPayload(packet.getCiphertext().getValue());
        // Padding (already set by the BinaryPacketParser)
        // Integrity protection (already set by the BinaryPacketParser)
        computations.setMacValid(packet.getMac().getValue().length == 0);
        computations.setPaddingValid(isPaddingValid(packet.getPadding().getValue()));
    }

    @Override
    public void decrypt(BlobPacket packet) throws CryptoException {
        packet.setPayload(packet.getCiphertext().getValue());
    }
}
