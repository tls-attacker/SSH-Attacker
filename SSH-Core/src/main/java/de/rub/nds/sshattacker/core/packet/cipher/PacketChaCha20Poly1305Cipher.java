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
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.AEADBadTagException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketChaCha20Poly1305Cipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
     * The chacha20-poly1305@openssh.com encryption algorithm employs two distinct cipher
     * instances, one instance of chacha20 to encrypt the packet length (without authentication) and
     * one instance of chacha20-poly1305 to encrypt the remaining contents (with authentication).
     * This encryption algorithm requires 512 bits of key material which is split into two separate
     * keys K_1 and K_2, where K_1 consists out of the second half of key bits.
     *
     * Source: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
     */
    /** ChaCha20 instance keyed with K_1 for packet length encryption / decryption. */
    private final AbstractCipher headerCipher;

    /** ChaCha20-Poly1305 instance keyed with K_2 for main packet encryption / decryption. */
    private final AbstractCipher mainCipher;

    public PacketChaCha20Poly1305Cipher(SshContext context, KeySet keySet, CipherMode mode) {
        super(context, keySet, EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM, null, mode);
        headerCipher =
                CipherFactory.getCipher(
                        encryptionAlgorithm,
                        Arrays.copyOfRange(
                                mode == CipherMode.ENCRYPT
                                        ? keySet.getWriteEncryptionKey(getLocalConnectionEndType())
                                        : keySet.getReadEncryptionKey(getLocalConnectionEndType()),
                                CryptoConstants.CHACHA20_KEY_SIZE,
                                2 * CryptoConstants.CHACHA20_KEY_SIZE),
                        false);
        mainCipher =
                CipherFactory.getCipher(
                        encryptionAlgorithm,
                        Arrays.copyOfRange(
                                mode == CipherMode.ENCRYPT
                                        ? keySet.getWriteEncryptionKey(getLocalConnectionEndType())
                                        : keySet.getReadEncryptionKey(getLocalConnectionEndType()),
                                0,
                                CryptoConstants.CHACHA20_KEY_SIZE),
                        true);
    }

    @Override
    protected void encrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getWriteEncryptionKey(getLocalConnectionEndType()));
        computations.setIv(
                packet.getSequenceNumber().getByteArray(DataFormatConstants.UINT64_SIZE));

        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(calculatePadding(packet.getPaddingLength().getValue()));
        packet.setLength(calculatePacketLength(packet));

        // Encryption of packet length
        byte[] encryptedPacketLength =
                headerCipher.encrypt(
                        packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH),
                        computations.getIv().getValue());
        computations.setAdditionalAuthenticatedData(encryptedPacketLength);
        // Encryption of remaining packet
        computations.setPlainPacketBytes(
                ArrayConverter.concatenate(
                        new byte[] {packet.getPaddingLength().getValue()},
                        packet.getCompressedPayload().getValue(),
                        packet.getPadding().getValue()));
        byte[] authenticatedCiphertext =
                mainCipher.encrypt(
                        computations.getPlainPacketBytes().getValue(),
                        computations.getIv().getValue(),
                        computations.getAdditionalAuthenticatedData().getValue());
        byte[] ciphertext =
                ArrayConverter.concatenate(
                        encryptedPacketLength,
                        Arrays.copyOfRange(
                                authenticatedCiphertext,
                                0,
                                authenticatedCiphertext.length
                                        - encryptionAlgorithm.getAuthTagSize()));
        byte[] mac =
                Arrays.copyOfRange(
                        authenticatedCiphertext,
                        authenticatedCiphertext.length - encryptionAlgorithm.getAuthTagSize(),
                        authenticatedCiphertext.length);
        packet.setCiphertext(ciphertext);
        packet.setMac(mac);
        computations.setEncryptedPacketFields(
                new HashSet<>(
                        Set.of(
                                BinaryPacketField.PACKET_LENGTH,
                                BinaryPacketField.PADDING_LENGTH,
                                BinaryPacketField.PAYLOAD,
                                BinaryPacketField.PADDING)));
        computations.setPaddingValid(true);
        computations.setMacValid(true);
    }

    @Override
    protected void encrypt(BlobPacket packet) throws CryptoException {
        byte[] iv =
                ArrayConverter.intToBytes(
                        context.getWriteSequenceNumber(), DataFormatConstants.UINT64_SIZE);
        packet.setCiphertext(
                mainCipher.encrypt(packet.getCompressedPayload().getValue(), iv, new byte[0]));
    }

    @Override
    protected void decrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getReadEncryptionKey(getLocalConnectionEndType()));
        computations.setIv(
                packet.getSequenceNumber().getByteArray(DataFormatConstants.UINT64_SIZE));
        computations.setAdditionalAuthenticatedData(
                Arrays.copyOfRange(
                        packet.getCiphertext().getValue(),
                        0,
                        BinaryPacketConstants.LENGTH_FIELD_LENGTH));

        try {
            byte[] authenticatedCiphertext =
                    ArrayConverter.concatenate(
                            Arrays.copyOfRange(
                                    packet.getCiphertext().getValue(),
                                    BinaryPacketConstants.LENGTH_FIELD_LENGTH,
                                    packet.getCiphertext().getValue().length),
                            packet.getMac().getValue());
            computations.setPlainPacketBytes(
                    mainCipher.decrypt(
                            authenticatedCiphertext,
                            computations.getIv().getValue(),
                            computations.getAdditionalAuthenticatedData().getValue()));
        } catch (AEADBadTagException e) {
            LOGGER.warn(
                    "Caught an AEADBadTagException while decrypting the binary packet - returning the packet without decryption",
                    e);
            computations.setMacValid(false);
            return;
        }
        computations.setEncryptedPacketFields(
                new HashSet<>(
                        Set.of(
                                BinaryPacketField.PACKET_LENGTH,
                                BinaryPacketField.PADDING_LENGTH,
                                BinaryPacketField.PAYLOAD,
                                BinaryPacketField.PADDING)));

        DecryptionParser parser =
                new DecryptionParser(computations.getPlainPacketBytes().getValue(), 0);
        packet.setPaddingLength(parser.parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setCompressedPayload(
                parser.parseByteArrayField(
                        packet.getLength().getValue()
                                - packet.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setPadding(parser.parseByteArrayField(packet.getPaddingLength().getValue()));

        // We got here, so the tag is valid
        computations.setMacValid(true);
        computations.setPaddingValid(isPaddingValid(packet.getPadding().getOriginalValue()));
    }

    @Override
    protected void decrypt(BlobPacket packet) throws CryptoException {
        byte[] iv =
                ArrayConverter.intToBytes(
                        context.getReadSequenceNumber(), DataFormatConstants.UINT64_SIZE);
        try {
            packet.setCompressedPayload(
                    mainCipher.decrypt(packet.getCiphertext().getValue(), iv, new byte[0]));
        } catch (AEADBadTagException e) {
            LOGGER.warn(
                    "Caught an AEADBadTagException while decrypting the blob packet - returning the packet without decryption",
                    e);
            // Trigger "none" cipher fallback to populate the compressedPayload data member
            // FIXME
            throw new CryptoException(
                    "Chacha20Poly1305 bad tag (BlobPacket). CompressedPayload was not set.");
        }
    }

    public AbstractCipher getHeaderCipher() {
        return headerCipher;
    }

    public AbstractCipher getMainCipher() {
        return mainCipher;
    }

    @Override
    public String toString() {
        return "PacketChaCha20Poly1305Cipher";
    }
}
