/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.checksum.CRC;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.mac.AbstractMac;
import de.rub.nds.sshattacker.core.crypto.mac.MacFactory;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.*;
import de.rub.nds.sshattacker.core.packet.cipher.keys.AbstractKeySet;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketMacedCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Cipher for encryption / decryption of packets. */
    private final AbstractCipher cipher;

    /** MAC for integrity protection of packets. */
    private final AbstractMac mac;

    /**
     * Next IV for packet processing. Might be null if the encryption algorithm does not use an IV.
     */
    private byte[] nextIv;

    public PacketMacedCipher(
            SshContext context,
            AbstractKeySet keySet,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm,
            CipherMode mode) {
        super(context, keySet, encryptionAlgorithm, macAlgorithm, mode);
        try {
            cipher =
                    CipherFactory.getCipher(
                            encryptionAlgorithm,
                            keySet == null
                                    ? null
                                    : mode == CipherMode.ENCRYPT
                                            ? keySet.getWriteEncryptionKey(
                                                    getLocalConnectionEndType())
                                            : keySet.getReadEncryptionKey(
                                                    getLocalConnectionEndType()));
            mac =
                    MacFactory.getMac(
                            macAlgorithm,
                            keySet == null
                                    ? null
                                    : mode == CipherMode.ENCRYPT
                                            ? keySet.getWriteIntegrityKey(
                                                    getLocalConnectionEndType())
                                            : keySet.getReadIntegrityKey(
                                                    getLocalConnectionEndType()));
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
                    "Unsupported encryption or MAC algorithm: "
                            + encryptionAlgorithm.name()
                            + " | "
                            + macAlgorithm.name());
        }

        if (encryptionAlgorithm.getIVSize() > 0) {
            // Encryption algorithm does use an IV
            assert keySet != null;
            nextIv =
                    mode == CipherMode.ENCRYPT
                            ? keySet.getWriteIv(getLocalConnectionEndType())
                            : keySet.getReadIv(getLocalConnectionEndType());
        }
    }

    private void calculateCrcChecksum(BinaryPacketSSHv1 binaryPacket) {
        CRC crc32 = new CRC();
        byte[] value = binaryPacket.getCompressedPayload().getValue();
        byte[] checksum = ArrayConverter.longToBytes(crc32.calculateCRC(value), 4);
        binaryPacket.setCrcChecksum(checksum);
    }

    @Override
    public void encrypt(BinaryPacketSSHv1 packet) {

        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        if (keySet != null) {
            computations.setEncryptionKey(
                    keySet.getWriteEncryptionKey(getLocalConnectionEndType()));
        }

        packet.setLength(
                packet.getCompressedPayload().getValue().length + 4); // +4 for CRC-Checksum

        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(calculatePadding(packet.getPaddingLength().getValue()));

        packet.setCompressedPayload(
                ArrayConverter.concatenate(
                        packet.getPadding().getValue(), packet.getCompressedPayload().getValue()));

        calculateCrcChecksum(packet);

        computations.setPlainPacketBytes(
                ArrayConverter.concatenate(
                        packet.getCompressedPayload().getValue(),
                        packet.getCrcChecksum().getValue()));
        try {
            encryptInner(packet);
        } catch (CryptoException e) {
            LOGGER.warn("Exception while encrypting Pz");
            throw new RuntimeException(e);
        }

        computations.setEncryptedPacketFields(
                Stream.of(BinaryPacketField.PAYLOAD).collect(Collectors.toSet()));
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
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
        }

        packet.setMac(
                mac.calculate(
                        packet.getSequenceNumber().getValue(),
                        computations.getAuthenticatedPacketBytes().getValue()));
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
        } else if (packet instanceof BinaryPacketSSHv1) {
            plainData =
                    ((BinaryPacketSSHv1) packet).getComputations().getPlainPacketBytes().getValue();
        } else {
            plainData = packet.getCompressedPayload().getValue();
        }

        if (encryptionAlgorithm.getIVSize() > 0) {
            // Encryption with IV
            byte[] iv = nextIv;
            if (packet instanceof BinaryPacket) {
                // Apply modifications to IV (if any)
                PacketCryptoComputations computations = ((BinaryPacket) packet).getComputations();
                computations.setIv(iv);
                iv = computations.getIv().getValue();
            } else if (packet instanceof BinaryPacketSSHv1) {
                // Apply modifications to IV (if any)
                PacketCryptoComputations computations =
                        ((BinaryPacketSSHv1) packet).getComputations();
                computations.setIv(iv);
                iv = computations.getIv().getValue();
            }
            packet.setCiphertext(cipher.encrypt(plainData, iv));
            nextIv = extractNextIv(nextIv, packet.getCiphertext().getOriginalValue());
        } else {
            // Encryption without IV
            packet.setCiphertext(cipher.encrypt(plainData));
        }
    }

    @Override
    public void decrypt(BinaryPacketSSHv1 packet) throws CryptoException {
        decryptInner(packet);

        DecryptionParser parser = new DecryptionParser(packet.getPayload().getValue());

        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(parser.parseByteArrayField(packet.getPaddingLength().getValue()));

        byte[] compressedPayload =
                parser.parseByteArrayField(
                        packet.getLength().getValue() - BinaryPacketConstants.CRC_FIELD_LENGHT);

        packet.setCrcChecksum(parser.parseByteArrayField(BinaryPacketConstants.CRC_FIELD_LENGHT));

        packet.setCompressedPayload(compressedPayload);
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
        LOGGER.debug("Padding Lenght:" + packet.getPaddingLength().getValue().intValue());
        packet.setCompressedPayload(
                parser.parseByteArrayField(
                        packet.getLength().getValue()
                                - packet.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setPadding(parser.parseByteArrayField(packet.getPaddingLength().getValue()));

        LOGGER.debug(
                "[bro] Compressed Payload:"
                        + ArrayConverter.bytesToHexString(
                                packet.getCompressedPayload().getValue()));

        if (isEncryptThenMac()) {
            computations.setEncryptedPacketFields(
                    Stream.of(
                                    BinaryPacketField.PADDING_LENGTH,
                                    BinaryPacketField.PAYLOAD,
                                    BinaryPacketField.PADDING)
                            .collect(Collectors.toSet()));

            computations.setAuthenticatedPacketBytes(
                    ArrayConverter.concatenate(
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
                            packet.getLength()
                                    .getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                            new byte[] {packet.getPaddingLength().getValue()},
                            packet.getCompressedPayload().getValue(),
                            packet.getPadding().getValue()));
        }

        // Verify MAC and padding
        byte[] shouldMac =
                mac.calculate(
                        packet.getSequenceNumber().getValue(),
                        computations.getAuthenticatedPacketBytes().getValue());
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
                    computations.setIv(nextIv);
                    byte[] remainingBlocksIv =
                            extractNextIv(
                                    nextIv,
                                    Arrays.copyOfRange(
                                            packet.getCiphertext().getValue(),
                                            0,
                                            firstBlock.length));
                    remainingBlocks =
                            cipher.decrypt(
                                    Arrays.copyOfRange(
                                            ciphertext, firstBlock.length, ciphertext.length),
                                    remainingBlocksIv);
                } else {
                    // Case 1b: Binary packet / First block decrypted / Cipher without IV
                    remainingBlocks =
                            cipher.decrypt(
                                    Arrays.copyOfRange(
                                            ciphertext, firstBlock.length, ciphertext.length));
                }
                plainData = ArrayConverter.concatenate(firstBlock, remainingBlocks);
            } else {
                if (encryptionAlgorithm.getIVSize() > 0) {
                    // Case 2a: Binary packet / First block not decrypted / Cipher with IV
                    computations.setIv(nextIv);
                    plainData =
                            cipher.decrypt(
                                    packet.getCiphertext().getValue(),
                                    computations.getIv().getValue());
                } else {
                    // Case 2b: Binary packet / First block not decrypted / Cipher without IV
                    plainData = cipher.decrypt(packet.getCiphertext().getValue());
                }
            }
            computations.setPlainPacketBytes(plainData);
            ModifiableByteArray plain_modifialbel = new ModifiableByteArray();
            plain_modifialbel.setOriginalValue(plainData);
            packet.setPayload(plain_modifialbel);
        } else {
            if (encryptionAlgorithm.getIVSize() > 0) {
                // Case 3a: Blob packet / Cipher with IV
                plainData = cipher.decrypt(packet.getCiphertext().getValue(), nextIv);
            } else {
                // Case 3b: Blob packet / Cipher without IV
                plainData = cipher.decrypt(packet.getCiphertext().getValue());
            }
            packet.setCompressedPayload(plainData);
            ModifiableByteArray plain_modifialbel = new ModifiableByteArray();
            plain_modifialbel.setOriginalValue(plainData);
            packet.setPayload(plain_modifialbel);
        }
        // Set the IV for the next packet if the encryption algorithm incorporates one
        if (encryptionAlgorithm.getIVSize() > 0) {
            nextIv = extractNextIv(nextIv, packet.getCiphertext().getValue());
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
                return ArrayConverter.bigIntegerToNullPaddedByteArray(
                        ctr, encryptionAlgorithm.getIVSize());
            default:
                throw new UnsupportedOperationException(
                        "Unable to extract initialization vector for mode: "
                                + encryptionAlgorithm.getMode());
        }
    }

    public byte[] getNextIv() {
        return nextIv;
    }

    public void setNextIv(byte[] nextIv) {
        this.nextIv = nextIv;
    }

    public AbstractCipher getCipher() {
        return cipher;
    }

    public AbstractMac getMac() {
        return mac;
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
