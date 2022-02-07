/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketGCMCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Cipher for encryption and integrity protection of outgoing packets. */
    private final EncryptionCipher encryptCipher;
    /** Cipher for decryption and integrity protection of incoming packets. */
    private final DecryptionCipher decryptCipher;
    /** Fixed part of the IV for packet encryption. */
    private final byte[] ivFixedEncryption;
    /** Fixed part of the IV for packet decryption. */
    private final byte[] ivFixedDecryption;
    /** Dynamic part of the encryption IV implemented as a counter variable. */
    private long ivCtrEncryption;
    /** Dynamic part of the decryption IV implemented as a counter variable. */
    private long ivCtrDecryption;

    public PacketGCMCipher(
            SshContext context, KeySet keySet, EncryptionAlgorithm encryptionAlgorithm) {
        super(context, keySet, encryptionAlgorithm, null);
        encryptCipher =
                CipherFactory.getEncryptionCipher(
                        encryptionAlgorithm, keySet, getLocalConnectionEndType());
        decryptCipher =
                CipherFactory.getDecryptionCipher(
                        encryptionAlgorithm, keySet, getLocalConnectionEndType());
        ivFixedEncryption =
                Arrays.copyOfRange(keySet.getWriteIv(getLocalConnectionEndType()), 0, 4);
        ivFixedDecryption = Arrays.copyOfRange(keySet.getReadIv(getLocalConnectionEndType()), 0, 4);
        ivCtrEncryption =
                Converter.byteArrayToLong(
                        Arrays.copyOfRange(keySet.getWriteIv(getLocalConnectionEndType()), 4, 12));
        ivCtrDecryption =
                Converter.byteArrayToLong(
                        Arrays.copyOfRange(keySet.getReadIv(getLocalConnectionEndType()), 4, 12));
    }

    @Override
    public void encrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getWriteEncryptionKey(getLocalConnectionEndType()));

        packet.setPaddingLength(calculatePaddingLength(packet));
        packet.setPadding(calculatePadding(packet.getPaddingLength().getValue()));
        packet.setLength(calculatePacketLength(packet));

        // AEAD encryption
        computations.setPlainPacketBytes(
                ArrayConverter.concatenate(
                        new byte[] {packet.getPaddingLength().getValue()},
                        packet.getCompressedPayload().getValue(),
                        packet.getPadding().getValue()));
        computations.setIv(
                ArrayConverter.concatenate(
                        ivFixedEncryption, ArrayConverter.longToUint64Bytes(ivCtrEncryption)));
        computations.setAdditionalAuthenticatedData(
                packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH));
        byte[] authenticatedCiphertext =
                encryptCipher.encrypt(
                        computations.getPlainPacketBytes().getValue(),
                        computations.getIv().getValue(),
                        computations.getAdditionalAuthenticatedData().getValue());
        byte[] ciphertext =
                Arrays.copyOfRange(
                        authenticatedCiphertext,
                        0,
                        authenticatedCiphertext.length - encryptionAlgorithm.getAuthTagSize());
        byte[] authTag =
                Arrays.copyOfRange(
                        authenticatedCiphertext,
                        authenticatedCiphertext.length - encryptionAlgorithm.getAuthTagSize(),
                        authenticatedCiphertext.length);
        packet.setCiphertext(ciphertext);
        packet.setMac(authTag);
        computations.setEncryptedPacketFields(
                Stream.of(
                                BinaryPacketField.PADDING_LENGTH,
                                BinaryPacketField.PAYLOAD,
                                BinaryPacketField.PADDING)
                        .collect(Collectors.toSet()));

        computations.setPaddingValid(true);
        computations.setMacValid(true);
        ivCtrEncryption++;
    }

    @Override
    public void encrypt(BlobPacket packet) throws CryptoException {
        byte[] iv =
                ArrayConverter.concatenate(
                        ivFixedEncryption, ArrayConverter.longToUint64Bytes(ivCtrEncryption));
        packet.setCiphertext(
                encryptCipher.encrypt(packet.getCompressedPayload().getValue(), iv, new byte[0]));
        ivCtrEncryption++;
    }

    @Override
    public void decrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getReadEncryptionKey(getLocalConnectionEndType()));

        computations.setIv(
                ArrayConverter.concatenate(
                        ivFixedDecryption, ArrayConverter.longToUint64Bytes(ivCtrDecryption)));
        computations.setAdditionalAuthenticatedData(
                packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH));
        try {
            computations.setPlainPacketBytes(
                    decryptCipher.decrypt(
                            ArrayConverter.concatenate(
                                    packet.getCiphertext().getValue(), packet.getMac().getValue()),
                            computations.getIv().getValue(),
                            computations.getAdditionalAuthenticatedData().getValue()));
        } catch (AEADBadTagException e) {
            LOGGER.warn(
                    "Caught an AEADBadTagException while decrypting the binary packet - returning the packet without decryption",
                    e);
            computations.setMacValid(false);
            ivCtrDecryption++;
            return;
        }
        computations.setEncryptedPacketFields(
                Stream.of(
                                BinaryPacketField.PADDING_LENGTH,
                                BinaryPacketField.PAYLOAD,
                                BinaryPacketField.PADDING)
                        .collect(Collectors.toSet()));

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
        ivCtrDecryption++;
    }

    @Override
    public void decrypt(BlobPacket packet) throws CryptoException {
        byte[] iv =
                ArrayConverter.concatenate(
                        ivFixedEncryption, ArrayConverter.longToUint64Bytes(ivCtrEncryption));
        try {
            packet.setCompressedPayload(
                    decryptCipher.decrypt(packet.getCiphertext().getValue(), iv, new byte[0]));
        } catch (AEADBadTagException e) {
            LOGGER.warn(
                    "Caught an AEADBadTagException while decrypting the blob packet - returning the packet without decryption",
                    e);
        }
        ivCtrDecryption++;
    }

    public EncryptionCipher getEncryptCipher() {
        return encryptCipher;
    }

    public DecryptionCipher getDecryptCipher() {
        return decryptCipher;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[Cipher: " + encryptionAlgorithm + "]";
    }
}
