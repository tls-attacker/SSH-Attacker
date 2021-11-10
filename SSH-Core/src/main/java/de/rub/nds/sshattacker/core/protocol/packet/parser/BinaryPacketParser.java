/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.crypto.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.packet.PacketCryptoComputations;
import java.util.Arrays;
import java.util.Collections;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketParser extends AbstractPacketParser<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PacketCipher activeDecryptCipher;

    public BinaryPacketParser(byte[] array, int startPosition, PacketCipher activeDecryptCipher) {
        super(array, startPosition);
        this.activeDecryptCipher = activeDecryptCipher;
    }

    @Override
    public BinaryPacket parse() {
        if (activeDecryptCipher.getEncryptionAlgorithm() == EncryptionAlgorithm.NONE) {
            return parseUnencryptedPacket();
        } else {
            try {
                return parseEncryptedPacket();
            } catch (CryptoException e) {
                LOGGER.warn("Caught a CryptoException while parsing an encrypted binary packet", e);
                return null;
            }
        }
    }

    private BinaryPacket parseUnencryptedPacket() {
        LOGGER.debug("Parsing unencrypted BinaryPacket");
        BinaryPacket binaryPacket = new BinaryPacket();

        // No packet fields are encrypted
        binaryPacket.prepareComputations();
        PacketCryptoComputations computations = binaryPacket.getComputations();
        computations.setEncryptedPacketFields(Collections.emptySet());

        // Parse the binary packet
        binaryPacket.setLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        computations.setPaddingLength(parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        binaryPacket.setPayload(
                parseByteArrayField(
                        binaryPacket.getLength().getValue()
                                - computations.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        computations.setPadding(parseByteArrayField(computations.getPaddingLength().getValue()));
        computations.setMac(
                parseByteArrayField(activeDecryptCipher.getMacAlgorithm().getOutputSize()));
        binaryPacket.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.debug("Packet length: {}", binaryPacket.getLength().getValue());
        LOGGER.debug("Padding length: {}", computations.getPaddingLength().getValue());
        LOGGER.debug("Payload: {}", ArrayConverter.bytesToHexString(binaryPacket.getPayload()));
        LOGGER.debug("Padding: {}", ArrayConverter.bytesToHexString(computations.getPadding()));
        LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(computations.getMac()));

        return binaryPacket;
    }

    private BinaryPacket parseEncryptedPacket() throws CryptoException {
        BinaryPacket binaryPacket = new BinaryPacket();

        // When using the encrypt-then-mac scheme: padding_length, payload and padding are encrypted
        binaryPacket.prepareComputations();
        PacketCryptoComputations computations = binaryPacket.getComputations();

        if (activeDecryptCipher.isEncryptThenMac()) {
            LOGGER.debug("Parsing encrypt-then-mac BinaryPacket");

            binaryPacket.setLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
            computations.setCiphertext(parseByteArrayField(binaryPacket.getLength().getValue()));
        } else {
            LOGGER.debug("Parsing encrypt-and-mac BinaryPacket");

            // Decrypt the length field of the binary packet
            int pointer = getPointer();
            byte[] firstBlock =
                    parseByteArrayField(
                            activeDecryptCipher.getEncryptionAlgorithm().getBlockSize());
            setPointer(pointer);
            byte[] decryptedBlock = activeDecryptCipher.getDecryptCipher().decrypt(firstBlock);
            computations.setPlainPacketBytes(decryptedBlock);
            computations.setPlainPacketBytesFirstBlockOnly(true);

            int packetLength =
                    ArrayConverter.bytesToInt(
                            Arrays.copyOfRange(
                                    decryptedBlock, 0, BinaryPacketConstants.LENGTH_FIELD_LENGTH));
            binaryPacket.setLength(packetLength);

            computations.setCiphertext(
                    parseByteArrayField(
                            BinaryPacketConstants.LENGTH_FIELD_LENGTH
                                    + binaryPacket.getLength().getValue()));
        }

        computations.setMac(
                parseByteArrayField(activeDecryptCipher.getMacAlgorithm().getOutputSize()));
        binaryPacket.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.debug("Packet length: {}", binaryPacket.getLength().getValue());
        LOGGER.debug("Encrypted packet bytes: {}", binaryPacket.getLength().getValue());

        return binaryPacket;
    }
}
