/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** The SSH context this packet cipher is used in. */
    protected final SshContext context;
    /** The key set used by the cipher. */
    protected final KeySet keySet;
    /** The encryption algorithm to use. */
    protected final EncryptionAlgorithm encryptionAlgorithm;
    /** The MAC algorithm to use. This may be null if using an AEAD encryption algorithm. */
    protected final MacAlgorithm macAlgorithm;
    /** The cipher mode (whether packages should be encrypted or decrypted by this cipher). */
    protected final CipherMode mode;

    public PacketCipher(
            SshContext context,
            KeySet keySet,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm,
            CipherMode mode) {
        this.context = context;
        this.keySet = keySet;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.macAlgorithm = macAlgorithm;
        this.mode = mode;
    }

    /**
     * Encrypts or decrypts the provided packet using this PacketCipher instance (the actual
     * operation performed depends on the mode provided to the constructor).
     *
     * @param packet The packet to encrypt or decrypt
     * @throws CryptoException Thrown whenever something crypto-related fatally fails
     */
    public final void process(BinaryPacket packet) throws CryptoException {
        if (mode == CipherMode.ENCRYPT) {
            encrypt(packet);
        } else {
            decrypt(packet);
        }
    }

    /**
     * Encrypts or decrypts the provided packet using this PacketCipher instance (the actual
     * operation performed depends on the mode provided to the constructor).
     *
     * @param packet The packet to encrypt or decrypt
     * @throws CryptoException Thrown whenever something crypto-related fatally fails
     */
    public final void process(BlobPacket packet) throws CryptoException {
        if (mode == CipherMode.ENCRYPT) {
            encrypt(packet);
        } else {
            decrypt(packet);
        }
    }

    protected abstract void encrypt(BinaryPacket packet) throws CryptoException;

    protected abstract void encrypt(BlobPacket packet) throws CryptoException;

    protected abstract void decrypt(BinaryPacket packet) throws CryptoException;

    protected abstract void decrypt(BlobPacket packet) throws CryptoException;

    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public KeySet getKeySet() {
        return keySet;
    }

    public CipherMode getMode() {
        return mode;
    }

    public Boolean isEncryptThenMac() {
        return macAlgorithm != null && macAlgorithm.isEncryptThenMacAlgorithm();
    }

    protected ConnectionEndType getLocalConnectionEndType() {
        return context.getConnection().getLocalConnectionEndType();
    }

    protected int calculatePacketLength(BinaryPacket packet) {
        return BinaryPacketConstants.PADDING_FIELD_LENGTH
                + packet.getCompressedPayload().getValue().length
                + packet.getPaddingLength().getValue();
    }

    protected byte[] calculatePadding(int paddingLength) {
        // For now, we use zero bytes as padding
        return new byte[paddingLength];
    }

    protected byte calculatePaddingLength(BinaryPacket packet) {
        int effectiveBlockSize = encryptionAlgorithm.getBlockSize();
        // If the block size of the cipher is smaller than 8, 8 is used as the block size
        if (effectiveBlockSize < BinaryPacketConstants.DEFAULT_BLOCK_SIZE) {
            effectiveBlockSize = BinaryPacketConstants.DEFAULT_BLOCK_SIZE;
        }

        int excessBytes =
                (packet.getCompressedPayload().getValue().length
                                + BinaryPacketConstants.PADDING_FIELD_LENGTH
                                + (isEncryptThenMac()
                                                || encryptionAlgorithm.getType()
                                                        == EncryptionAlgorithmType.AEAD
                                        ? 0
                                        : BinaryPacketConstants.PACKET_FIELD_LENGTH))
                        % effectiveBlockSize;

        int paddingLength = effectiveBlockSize - excessBytes;
        if (paddingLength < BinaryPacketConstants.MIN_PADDING_LENGTH) {
            paddingLength += effectiveBlockSize;
        }
        return (byte) paddingLength;
    }

    protected boolean isPaddingValid(byte[] padding) {
        // Any padding shorter than 4 bytes and longer than 255 bytes is invalid by specification
        return padding.length >= 4 && padding.length <= 255;
    }

    protected static class DecryptionParser extends Parser<Object> {

        /*public DecryptionParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }*/

        public DecryptionParser(byte[] array) {
            super(new ByteArrayInputStream(array));
        }

        public DecryptionParser(byte[] array, int offset) {
            super(new ByteArrayInputStream(Arrays.copyOfRange(array, offset, array.length)));

            byte[] new_array = Arrays.copyOfRange(array, offset, array.length);
            LOGGER.debug(
                    "[bro] New Bytarray with lenght {} :  {}",
                    new_array.length,
                    ArrayConverter.bytesToHexString(new_array));
            // super(new ByteArrayInputStream(Arrays.copyOfRange(array, offset, array.length-1)));
        }

        @Override
        public void parse(Object t) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }

        @Override
        public int parseIntField(int length) {
            return super.parseIntField(length);
        }

        @Override
        public byte parseByteField(int length) {
            return super.parseByteField(length);
        }

        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }
    }
}
