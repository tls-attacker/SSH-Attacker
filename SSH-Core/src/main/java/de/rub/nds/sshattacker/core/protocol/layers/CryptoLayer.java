/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.layers;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.DecryptionException;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.BinaryPacketSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CryptoLayer {

    protected static final Logger LOGGER = LogManager.getLogger();
    protected final SshContext context;
    protected final EncryptionAlgorithm encryptionAlgorithm;
    protected final MacAlgorithm macAlgorithm;

    protected CryptoLayer(
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm,
            SshContext context) {
        this.context = context;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.macAlgorithm = macAlgorithm;
    }

    protected abstract byte[] encrypt(byte[] plaintext);

    protected abstract byte[] decrypt(byte[] ciphertext);

    protected abstract byte[] computeMAC(byte[] input);

    protected abstract void verifyMAC(byte[] input, byte[] mac);

    private void computePacketFields(BinaryPacket packet, boolean encryptedPacketLength) {
        packet.computePaddingLength(
                (byte) getEncryptionAlgorithm().getBlockSize(), encryptedPacketLength);
        packet.generatePadding();
        packet.computePacketLength();
    }

    private byte[] encryptAndMac(BinaryPacket packet) {
        computePacketFields(packet, true);
        byte[] serializedPacket = new BinaryPacketSerializer(packet).serializeForEncryption();
        byte[] encryptedPacket = encrypt(serializedPacket);
        byte[] toMac =
                ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(
                                context.getSequenceNumber(), DataFormatConstants.INT32_SIZE),
                        serializedPacket);
        byte[] mac = computeMAC(toMac);

        // Support for HMAC_SHA1_96 and similar algorithms
        if (mac.length > getMacAlgorithm().getOutputSize()) {
            LOGGER.info(
                    "MAC needs to be shorter, expected "
                            + getMacAlgorithm().getOutputSize()
                            + " but got "
                            + mac.length);
            mac = Arrays.copyOfRange(mac, 0, getMacAlgorithm().getOutputSize());
        }

        return ArrayConverter.concatenate(encryptedPacket, mac);
    }

    private byte[] encryptThenMac(BinaryPacket packet) {
        computePacketFields(packet, false);
        byte[] serializedPacket = new BinaryPacketSerializer(packet).serializeForETMEncryption();
        LOGGER.info("About to encrypt packet with length " + serializedPacket.length);
        byte[] encryptedPacket = encrypt(serializedPacket);
        byte[] packetLength =
                ArrayConverter.intToBytes(
                        packet.getPacketLength().getValue(),
                        BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.info("Package length is: " + Arrays.toString(packetLength));
        byte[] toMac =
                ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(
                                context.getSequenceNumber(), DataFormatConstants.INT32_SIZE),
                        packetLength,
                        encryptedPacket);
        byte[] mac = computeMAC(toMac);

        // Support for HMAC_SHA1_96_ETM_OPENSSH_COM and similar algorithms
        if (mac.length > getMacAlgorithm().getOutputSize()) {
            LOGGER.info(
                    "MAC needs to be shorter, expected "
                            + getMacAlgorithm().getOutputSize()
                            + " but got "
                            + mac.length);
            mac = Arrays.copyOfRange(mac, 0, getMacAlgorithm().getOutputSize());
        }

        return ArrayConverter.concatenate(packetLength, encryptedPacket, mac);
    }

    private byte[] decryptEAM(byte[] encryptedPacket) {
        try {
            byte[] firstBlock =
                    Arrays.copyOfRange(encryptedPacket, 0, encryptionAlgorithm.getBlockSize());
            byte[] decryptedFirstBlock = decrypt(firstBlock);
            int packetLength =
                    ArrayConverter.bytesToInt(
                            Arrays.copyOfRange(
                                    decryptedFirstBlock,
                                    0,
                                    BinaryPacketConstants.LENGTH_FIELD_LENGTH));
            int macStart = BinaryPacketConstants.LENGTH_FIELD_LENGTH + packetLength;
            int macEnd = macStart + macAlgorithm.getOutputSize();
            byte[] mac = Arrays.copyOfRange(encryptedPacket, macStart, macEnd);
            byte[] toDecrypt =
                    Arrays.copyOfRange(
                            encryptedPacket, encryptionAlgorithm.getBlockSize(), macStart);
            byte[] decrypted = decrypt(toDecrypt);

            // TODO: MAC verification

            return ArrayConverter.concatenate(decryptedFirstBlock, decrypted, mac);
        } catch (Exception e) {
            throw new DecryptionException("Unable to decrypt packet using \"Encrypt-and-MAC\"", e);
        }
    }

    private byte[] decryptETM(byte[] encryptedPacket) {
        try {
            byte[] serializedPacketLength =
                    Arrays.copyOfRange(
                            encryptedPacket, 0, BinaryPacketConstants.LENGTH_FIELD_LENGTH);
            int packetLength = ArrayConverter.bytesToInt(serializedPacketLength);
            int macStart = BinaryPacketConstants.LENGTH_FIELD_LENGTH + packetLength;
            int macEnd = macStart + macAlgorithm.getOutputSize();
            byte[] mac = Arrays.copyOfRange(encryptedPacket, macStart, macEnd);
            byte[] toDecrypt =
                    Arrays.copyOfRange(
                            encryptedPacket, BinaryPacketConstants.LENGTH_FIELD_LENGTH, macStart);
            byte[] decrypted = decrypt(toDecrypt);

            // TODO: MAC verification

            return ArrayConverter.concatenate(serializedPacketLength, decrypted, mac);
        } catch (Exception e) {
            throw new DecryptionException("Unable to decrypt packet using \"Encrypt-then-MAC\"", e);
        }
    }

    private byte[] decryptPacket(byte[] encryptedPacket) {
        if (macAlgorithm.isEncryptThenMacAlgorithm()) {
            return decryptETM(encryptedPacket);
        } else {
            return decryptEAM(encryptedPacket);
        }
    }

    public byte[] encryptPacket(BinaryPacket packet) {
        if (macAlgorithm.isEncryptThenMacAlgorithm()) {
            return encryptThenMac(packet);
        } else {
            return encryptAndMac(packet);
        }
    }

    public byte[] decryptBinaryPackets(byte[] encryptedPackets) {
        byte[] completeDecrypted = new byte[0];
        while (encryptedPackets.length
                >= encryptionAlgorithm.getBlockSize() + macAlgorithm.getOutputSize()) {
            byte[] decrypted = decryptPacket(encryptedPackets);
            completeDecrypted = ArrayConverter.concatenate(completeDecrypted, decrypted);
            encryptedPackets =
                    Arrays.copyOfRange(encryptedPackets, decrypted.length, encryptedPackets.length);
        }
        return completeDecrypted;
    }

    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }
}
