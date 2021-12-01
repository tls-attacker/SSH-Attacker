/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.mac.MacFactory;
import de.rub.nds.sshattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketMacedCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** MAC for verification of incoming packets. */
    private final WrappedMac readMac;
    /** MAC instance for macing outgoing packets. */
    private final WrappedMac writeMac;

    public PacketMacedCipher(
            SshContext context,
            KeySet keySet,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm) {
        super(context, keySet, encryptionAlgorithm, macAlgorithm);
        try {
            encryptCipher =
                    CipherFactory.getEncryptionCipher(
                            encryptionAlgorithm, keySet, getLocalConnectionEndType());
            decryptCipher =
                    CipherFactory.getDecryptionCipher(
                            encryptionAlgorithm, keySet, getLocalConnectionEndType());
            readMac = MacFactory.getReadMac(macAlgorithm, keySet, getLocalConnectionEndType());
            writeMac = MacFactory.getWriteMac(macAlgorithm, keySet, getLocalConnectionEndType());
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
                    "Unsupported encryption or MAC algorithm: "
                            + encryptionAlgorithm.name()
                            + " | "
                            + macAlgorithm.name());
        }
    }

    @Override
    public void encrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        if (keySet != null) {
            computations.setEncryptionKey(
                    keySet.getWriteEncryptionKey(getLocalConnectionEndType()));
            computations.setIntegrityKey(keySet.getWriteIntegrityKey(getLocalConnectionEndType()));
        }

        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(calculatePadding(packet.getPaddingLength().getValue()));
        packet.setLength(calculatePacketLength(packet));

        if (isEncryptThenMac()) {
            // Encryption
            computations.setPlainPacketBytes(
                    ArrayConverter.concatenate(
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
            packet.setCiphertext(
                    encryptCipher.encrypt(computations.getPlainPacketBytes().getValue()));
            computations.setEncryptedPacketFields(
                    Stream.of(
                                    BinaryPacketField.PADDING_LENGTH,
                                    BinaryPacketField.PAYLOAD,
                                    BinaryPacketField.PADDING)
                            .collect(Collectors.toSet()));

            // Integrity protection
            computations.setAuthenticatedPacketBytes(
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    packet.getSequenceNumber().getValue(),
                                    DataFormatConstants.INT32_SIZE),
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            packet.getCiphertext().getValue()));
        } else {
            // Encryption
            computations.setPlainPacketBytes(
                    ArrayConverter.concatenate(
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
            packet.setCiphertext(
                    encryptCipher.encrypt(computations.getPlainPacketBytes().getValue()));
            computations.setEncryptedPacketFields(
                    Stream.of(
                                    BinaryPacketField.PACKET_LENGTH,
                                    BinaryPacketField.PADDING_LENGTH,
                                    BinaryPacketField.PAYLOAD,
                                    BinaryPacketField.PADDING)
                            .collect(Collectors.toSet()));

            // Integrity protection
            computations.setAuthenticatedPacketBytes(
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    packet.getSequenceNumber().getValue(),
                                    DataFormatConstants.INT32_SIZE),
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
        }

        packet.setMac(writeMac.calculate(computations.getAuthenticatedPacketBytes().getValue()));
        computations.setPaddingValid(true);
        computations.setMacValid(true);
    }

    @Override
    public void encrypt(BlobPacket packet) throws CryptoException {
        packet.setCiphertext(
                encryptCipher.encrypt(packet.getCompressedPayload().getValue(), new byte[0]));
    }

    @Override
    public void decrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        if (keySet != null) {
            computations.setEncryptionKey(keySet.getReadEncryptionKey(getLocalConnectionEndType()));
            computations.setIntegrityKey(keySet.getReadIntegrityKey(getLocalConnectionEndType()));
        }

        // Decryption
        if (computations.isPlainPacketBytesFirstBlockOnly()) {
            // The first block has already been decrypted by the parser - only decrypt the remaining
            // blocks (if any)
            byte[] firstBlock = computations.getPlainPacketBytes().getOriginalValue();
            byte[] ciphertext = packet.getCiphertext().getValue();
            byte[] remainingBlocks =
                    decryptCipher.decrypt(
                            Arrays.copyOfRange(ciphertext, firstBlock.length, ciphertext.length));
            computations.setPlainPacketBytes(
                    ArrayConverter.concatenate(firstBlock, remainingBlocks));
        } else {
            computations.setPlainPacketBytes(
                    decryptCipher.decrypt(packet.getCiphertext().getValue()));
        }

        DecryptionParser parser =
                new DecryptionParser(
                        computations.getPlainPacketBytes().getValue(),
                        isEncryptThenMac() ? 0 : BinaryPacketConstants.PACKET_FIELD_LENGTH);
        packet.setPaddingLength(parser.parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setCompressedPayload(
                parser.parseByteArrayField(
                        packet.getLength().getValue()
                                - packet.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setPadding(parser.parseByteArrayField(packet.getPaddingLength().getValue()));

        if (isEncryptThenMac()) {
            computations.setEncryptedPacketFields(
                    Stream.of(
                                    BinaryPacketField.PADDING_LENGTH,
                                    BinaryPacketField.PAYLOAD,
                                    BinaryPacketField.PADDING)
                            .collect(Collectors.toSet()));

            computations.setAuthenticatedPacketBytes(
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    packet.getSequenceNumber().getValue(),
                                    DataFormatConstants.INT32_SIZE),
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            packet.getCiphertext().getValue()));
        } else {
            computations.setEncryptedPacketFields(
                    Stream.of(
                                    BinaryPacketField.PACKET_LENGTH,
                                    BinaryPacketField.PADDING,
                                    BinaryPacketField.PAYLOAD,
                                    BinaryPacketField.PADDING_LENGTH)
                            .collect(Collectors.toSet()));

            computations.setAuthenticatedPacketBytes(
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    packet.getSequenceNumber().getValue(),
                                    DataFormatConstants.INT32_SIZE),
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
        }

        // Verify MAC and padding
        byte[] shouldMac = readMac.calculate(computations.getAuthenticatedPacketBytes().getValue());
        computations.setMacValid(Arrays.equals(shouldMac, packet.getMac().getValue()));
        computations.setPaddingValid(isPaddingValid(packet.getPadding().getOriginalValue()));
    }

    @Override
    public void decrypt(BlobPacket packet) throws CryptoException {
        packet.setCompressedPayload(decryptCipher.decrypt(packet.getCiphertext().getValue()));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
                + "[Cipher: "
                + encryptionAlgorithm
                + ", MAC: "
                + macAlgorithm
                + "]";
    }
}
