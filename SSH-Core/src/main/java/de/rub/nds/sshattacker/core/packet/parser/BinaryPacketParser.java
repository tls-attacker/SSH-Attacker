/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
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
        LOGGER.debug("Parsing BinaryPacket from serialized bytes:");
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
        LOGGER.debug("Binary packet structure: Unencrypted");
        BinaryPacket binaryPacket = new BinaryPacket();

        // No packet fields are encrypted
        binaryPacket.prepareComputations();
        PacketCryptoComputations computations = binaryPacket.getComputations();
        computations.setEncryptedPacketFields(Collections.emptySet());

        // Parse the binary packet
        binaryPacket.setLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        binaryPacket.setPaddingLength(parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        binaryPacket.setCiphertext(
                parseByteArrayField(
                        binaryPacket.getLength().getValue()
                                - binaryPacket.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        binaryPacket.setPadding(parseByteArrayField(binaryPacket.getPaddingLength().getValue()));
        binaryPacket.setMac(
                parseByteArrayField(activeDecryptCipher.getMacAlgorithm().getOutputSize()));
        binaryPacket.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.trace(
                "Complete packet bytes: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getCompletePacketBytes().getValue()));
        LOGGER.debug("Packet length: {}", binaryPacket.getLength().getValue());
        LOGGER.debug("Padding length: {}", binaryPacket.getPaddingLength().getValue());
        LOGGER.debug("Payload: {}", ArrayConverter.bytesToHexString(binaryPacket.getCiphertext()));
        LOGGER.debug("Padding: {}", ArrayConverter.bytesToHexString(binaryPacket.getPadding()));
        LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(binaryPacket.getMac()));

        return binaryPacket;
    }

    private BinaryPacket parseEncryptedPacket() throws CryptoException {
        BinaryPacket binaryPacket = new BinaryPacket();
        if (activeDecryptCipher.getEncryptionAlgorithm().getType()
                == EncryptionAlgorithmType.AEAD) {
            LOGGER.debug("Packet structure: AEAD");
            parseAEADPacket(binaryPacket);
        } else if (activeDecryptCipher.isEncryptThenMac()) {
            LOGGER.debug("Packet structure: Encrypt-then-MAC");
            parseETMPacket(binaryPacket);
        } else {
            LOGGER.debug("Packet structure: Encrypt-and-MAC");
            parseEAMPacket(binaryPacket);
        }
        binaryPacket.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.trace(
                "Complete packet bytes: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getCompletePacketBytes().getValue()));
        LOGGER.debug("Packet length: {}", binaryPacket.getLength().getValue());
        LOGGER.debug(
                "Encrypted packet bytes: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getCiphertext().getValue()));
        if (activeDecryptCipher.getEncryptionAlgorithm().getType()
                == EncryptionAlgorithmType.AEAD) {
            LOGGER.debug(
                    "Authentication tag: {}",
                    ArrayConverter.bytesToHexString(binaryPacket.getMac()));
        } else {
            LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(binaryPacket.getMac()));
        }
        return binaryPacket;
    }

    private void parseAEADPacket(BinaryPacket binaryPacket) {
        /*
         * Encrypted AEAD packet structure:
         *  uint32  packet_length
         *  byte[n] ciphertext      ; n = packet_length
         *  byte[m] auth_tag        ; m = length of authentication tag
         */
        binaryPacket.setLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        binaryPacket.setCiphertext(parseByteArrayField(binaryPacket.getLength().getValue()));
        binaryPacket.setMac(
                parseByteArrayField(activeDecryptCipher.getEncryptionAlgorithm().getAuthTagSize()));
    }

    private void parseETMPacket(BinaryPacket binaryPacket) {
        /*
         * Encrypted encrypt-then-mac packet structure:
         *  uint32  packet_length
         *  byte[n] ciphertext      ; n = packet_length
         *  byte[m] mac             ; m = length of mac output
         */
        binaryPacket.setLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        binaryPacket.setCiphertext(parseByteArrayField(binaryPacket.getLength().getValue()));
        binaryPacket.setMac(
                parseByteArrayField(activeDecryptCipher.getMacAlgorithm().getOutputSize()));
    }

    private void parseEAMPacket(BinaryPacket binaryPacket) throws CryptoException {
        binaryPacket.prepareComputations();
        PacketCryptoComputations computations = binaryPacket.getComputations();
        /*
         * Encrypted encrypt-and-mac packet structure:
         *  byte[n] ciphertext      ; n = 4 + packet_length (decryption of first block required)
         *  byte[m] mac             ; m = length of mac output
         */
        int pointer = getPointer();
        byte[] firstBlock =
                parseByteArrayField(activeDecryptCipher.getEncryptionAlgorithm().getBlockSize());
        setPointer(pointer);
        byte[] decryptedBlock = activeDecryptCipher.getDecryptCipher().decrypt(firstBlock);
        computations.setPlainPacketBytes(decryptedBlock, true);

        binaryPacket.setLength(
                ArrayConverter.bytesToInt(
                        Arrays.copyOfRange(
                                decryptedBlock, 0, BinaryPacketConstants.LENGTH_FIELD_LENGTH)));
        binaryPacket.setCiphertext(
                parseByteArrayField(
                        BinaryPacketConstants.LENGTH_FIELD_LENGTH
                                + binaryPacket.getLength().getValue()));
        binaryPacket.setMac(
                parseByteArrayField(activeDecryptCipher.getMacAlgorithm().getOutputSize()));
    }
}
