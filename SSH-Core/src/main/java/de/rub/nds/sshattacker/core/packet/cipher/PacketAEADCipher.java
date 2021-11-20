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
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.PacketCryptoComputations;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketAEADCipher extends PacketCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public PacketAEADCipher(
            SshContext context, KeySet keySet, EncryptionAlgorithm encryptionAlgorithm) {
        super(context, keySet, encryptionAlgorithm, null);
        encryptCipher =
                CipherFactory.getEncryptionCipher(
                        encryptionAlgorithm, keySet, getLocalConnectionEndType());
        decryptCipher =
                CipherFactory.getDecryptionCipher(
                        encryptionAlgorithm, keySet, getLocalConnectionEndType());
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
                        packet.getPayload().getValue(),
                        packet.getPadding().getValue()));
        computations.setAdditionalAuthenticatedData(
                packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH));
        byte[] authenticatedCiphertext =
                encryptCipher.encrypt(
                        computations.getPlainPacketBytes().getValue(),
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
    }

    @Override
    public void encrypt(BlobPacket packet) throws CryptoException {
        packet.setCiphertext(encryptCipher.encrypt(packet.getPayload().getValue(), new byte[0]));
    }

    @Override
    public void decrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getReadEncryptionKey(getLocalConnectionEndType()));

        computations.setAdditionalAuthenticatedData(
                packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH));
        try {
            computations.setPlainPacketBytes(
                    decryptCipher.decrypt(
                            ArrayConverter.concatenate(
                                    packet.getCiphertext().getValue(), packet.getMac().getValue()),
                            computations.getAdditionalAuthenticatedData().getValue()));
        } catch (AEADBadTagException e) {
            LOGGER.warn(
                    "Caught an AEADBadTagException while decrypting the binary packet - returning the packet without decryption",
                    e);
            computations.setMacValid(false);
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
        packet.setPayload(
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
    public void decrypt(BlobPacket packet) throws CryptoException {
        packet.setPayload(decryptCipher.decrypt(packet.getCiphertext().getValue()));
    }
}
