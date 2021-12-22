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
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.crypto.mac.MacFactory;
import de.rub.nds.sshattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketMacedCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Cipher for encryption of outgoing packets. */
    private final EncryptionCipher encryptCipher;
    /** Cipher for decryption of incoming packets. */
    private final DecryptionCipher decryptCipher;
    /** MAC for verification of incoming packets. */
    private final WrappedMac readMac;
    /** MAC instance for macing outgoing packets. */
    private final WrappedMac writeMac;

    /**
     * Next IV for packet encryption. Might be null if the encryption algorithm does not use an IV.
     */
    private byte[] nextEncryptionIv;
    /**
     * Next IV for packet decryption. Might be null if the encryption algorithm does not use an IV.
     */
    private byte[] nextDecryptionIv;

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

        if (encryptionAlgorithm.getIVSize() > 0) {
            // Encryption algorithm does use an IV
            nextEncryptionIv = keySet.getWriteIv(getLocalConnectionEndType());
            nextDecryptionIv = keySet.getReadIv(getLocalConnectionEndType());
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
            encryptInner(packet);
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
            encryptInner(packet);
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
        encryptInner(packet);
    }

    private void encryptInner(AbstractPacket packet) throws CryptoException {
        byte[] plainData;
        if (packet instanceof BinaryPacket) {
            plainData = ((BinaryPacket) packet).getComputations().getPlainPacketBytes().getValue();
        } else {
            plainData = packet.getCompressedPayload().getValue();
        }

        if (encryptionAlgorithm.getIVSize() > 0) {
            // Encryption with IV
            byte[] iv = nextEncryptionIv;
            if (packet instanceof BinaryPacket) {
                // Apply modifications to IV (if any)
                PacketCryptoComputations computations = ((BinaryPacket) packet).getComputations();
                computations.setIv(iv);
                iv = computations.getIv().getValue();
            }
            packet.setCiphertext(encryptCipher.encrypt(plainData, iv));
            nextEncryptionIv =
                    extractNextIv(nextEncryptionIv, packet.getCiphertext().getOriginalValue());
        } else {
            // Encryption without IV
            packet.setCiphertext(encryptCipher.encrypt(plainData));
        }
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

        decryptInner(packet);

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
        decryptInner(packet);
    }

    private void decryptInner(AbstractPacket packet) throws CryptoException {
        byte[] plainData;
        if (packet instanceof BinaryPacket) {
            PacketCryptoComputations computations = ((BinaryPacket) packet).getComputations();
            if (computations.isPlainPacketBytesFirstBlockOnly()) {
                byte[] firstBlock = computations.getPlainPacketBytes().getOriginalValue();
                byte[] ciphertext = packet.getCiphertext().getValue();
                byte[] remainingBlocks;
                if (encryptionAlgorithm.getIVSize() > 0) {
                    // Case 1a: Binary packet / First block decrypted / Cipher with IV
                    computations.setIv(nextDecryptionIv);
                    byte[] remainingBlocksIv =
                            extractNextIv(
                                    nextDecryptionIv,
                                    Arrays.copyOfRange(
                                            packet.getCiphertext().getValue(),
                                            0,
                                            firstBlock.length));
                    remainingBlocks =
                            decryptCipher.decrypt(
                                    Arrays.copyOfRange(
                                            ciphertext, firstBlock.length, ciphertext.length),
                                    remainingBlocksIv);
                } else {
                    // Case 1b: Binary packet / First block decrypted / Cipher without IV
                    remainingBlocks =
                            decryptCipher.decrypt(
                                    Arrays.copyOfRange(
                                            ciphertext, firstBlock.length, ciphertext.length));
                }
                plainData = ArrayConverter.concatenate(firstBlock, remainingBlocks);
            } else {
                if (encryptionAlgorithm.getIVSize() > 0) {
                    // Case 2a: Binary packet / First block not decrypted / Cipher with IV
                    computations.setIv(nextDecryptionIv);
                    plainData =
                            decryptCipher.decrypt(
                                    packet.getCiphertext().getValue(),
                                    computations.getIv().getValue());
                } else {
                    // Case 2b: Binary packet / First block not decrypted / Cipher without IV
                    plainData = decryptCipher.decrypt(packet.getCiphertext().getValue());
                }
            }
            computations.setPlainPacketBytes(plainData);
        } else {
            if (encryptionAlgorithm.getIVSize() > 0) {
                // Case 3a: Blob packet / Cipher with IV
                plainData =
                        decryptCipher.decrypt(packet.getCiphertext().getValue(), nextDecryptionIv);
            } else {
                // Case 3b: Blob packet / Cipher without IV
                plainData = decryptCipher.decrypt(packet.getCiphertext().getValue());
            }
            packet.setCompressedPayload(plainData);
        }
        // Set the IV for the next packet if the encryption algorithm incorporates one
        if (encryptionAlgorithm.getIVSize() > 0) {
            nextDecryptionIv = extractNextIv(nextDecryptionIv, packet.getCiphertext().getValue());
        }
    }

    private byte[] extractNextIv(byte[] iv, byte[] ct) {
        switch (encryptionAlgorithm.getMode()) {
            case CBC:
                // Next IV in CBC mode is the last block of the current ciphertext
                return Arrays.copyOfRange(
                        ct, ct.length - encryptionAlgorithm.getBlockSize(), ct.length);
            case CTR:
                // Next IV in CTR mode is the old counter / iv incremented by the number of blocks
                // of the ciphertext
                BigInteger ctr = new BigInteger(1, iv);
                int ctBlocks = ct.length / encryptionAlgorithm.getBlockSize();
                ctr = ctr.add(BigInteger.valueOf(ctBlocks));
                // Wrap around if the counter would exceed the length of the iv
                // This is rather unlikely to occur even once, but this is the OpenSSL behavior when
                // overflowing
                ctr =
                        ctr.mod(
                                BigInteger.ONE.shiftLeft(
                                        Byte.SIZE * encryptionAlgorithm.getIVSize()));
                return ArrayConverter.bigIntegerToByteArray(ctr);
            default:
                throw new UnsupportedOperationException(
                        "Unable to extract initialization vector for mode: "
                                + encryptionAlgorithm.getMode());
        }
    }

    public byte[] getNextEncryptionIv() {
        return nextEncryptionIv;
    }

    public byte[] getNextDecryptionIv() {
        return nextDecryptionIv;
    }

    public EncryptionCipher getEncryptCipher() {
        return encryptCipher;
    }

    public DecryptionCipher getDecryptCipher() {
        return decryptCipher;
    }

    public WrappedMac getReadMac() {
        return readMac;
    }

    public WrappedMac getWriteMac() {
        return writeMac;
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
