/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.packet.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.packet.keys.KeySet;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.packet.PacketCryptoComputations;
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
        LOGGER.debug("Encrypting binary packet:");
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getWriteEncryptionKey(getLocalConnectionEndType()));

        computations.setPaddingLength(calculatePaddingLength(packet));
        computations.setPadding(calculatePadding(computations.getPaddingLength().getValue()));
        LOGGER.debug(
                "Padding: "
                        + ArrayConverter.bytesToHexString(computations.getPadding().getValue()));
        packet.setLength(calculatePacketLength(packet));

        // AEAD encryption
        computations.setPlainPacketBytes(
                ArrayConverter.concatenate(
                        new byte[] {computations.getPaddingLength().getValue()},
                        packet.getPayload().getValue(),
                        computations.getPadding().getValue()));
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
        computations.setCiphertext(ciphertext);
        computations.setMac(authTag);
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
    public void decrypt(BinaryPacket packet) throws CryptoException {
        if (packet.getComputations() == null) {
            LOGGER.warn("Packet computations are not prepared.");
            packet.prepareComputations();
        }
        LOGGER.debug("Decrypting binary packet:");
        PacketCryptoComputations computations = packet.getComputations();

        computations.setEncryptionKey(keySet.getReadEncryptionKey(getLocalConnectionEndType()));

        computations.setAdditionalAuthenticatedData(
                packet.getLength().getByteArray(BinaryPacketConstants.PACKET_FIELD_LENGTH));
        try {
            computations.setPlainPacketBytes(
                    decryptCipher.decrypt(
                            ArrayConverter.concatenate(
                                    computations.getCiphertext().getValue(),
                                    computations.getMac().getValue()),
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
        computations.setPaddingLength(
                parser.parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        packet.setPayload(
                parser.parseByteArrayField(
                        packet.getLength().getValue()
                                - computations.getPaddingLength().getValue()
                                - BinaryPacketConstants.PADDING_FIELD_LENGTH));
        computations.setPadding(
                parser.parseByteArrayField(computations.getPaddingLength().getValue()));

        // We got here, so the tag is valid
        computations.setMacValid(true);
        computations.setPaddingValid(isPaddingValid(computations.getPadding().getOriginalValue()));
    }
}
