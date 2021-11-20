/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketDecryptor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.packet.crypto.PacketDecryptor;
import de.rub.nds.sshattacker.core.packet.crypto.PacketEncryptor;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.preparator.AbstractPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.AbstractPacketSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext context;

    private final AbstractPacketDecryptor decryptor;
    private final AbstractPacketEncryptor encryptor;

    private int writeEpoch = 0;
    private int readEpoch = 0;

    public AbstractPacketLayer(SshContext context) {
        this.context = context;
        encryptor = new PacketEncryptor(PacketCipherFactory.getNoneCipher(context), context);
        decryptor = new PacketDecryptor(PacketCipherFactory.getNoneCipher(context), context);
    }

    /**
     * Tries to parse rawBytes into AbstractPackets. Due to the nature of SSH encryption, this does
     * include decryption of the packet. If this is not possible a Parser Exception or Crypto
     * Exception is thrown.
     *
     * @param rawBytes Bytes to parse
     * @return List of parsed packets
     * @throws ParserException Thrown whenever parsing the provided bytes fails
     */
    public abstract Stream<AbstractPacket> parsePackets(byte[] rawBytes)
            throws ParserException, CryptoException;

    /**
     * Tries to parse rawBytes into AbstractPackets. Due to the nature of SSH encryption, this does
     * include decryption of the packet. Exception which might occur are handled.
     *
     * @param rawBytes Bytes to parse
     * @return List of parsed packets
     */
    public abstract Stream<AbstractPacket> parsePacketsSoftly(byte[] rawBytes);

    protected void decryptPacket(AbstractPacket packet) {
        packet.prepareComputations();
        getDecryptor().decrypt(packet);
    }

    public byte[] preparePacket(AbstractPacket packet) {
        AbstractPacketPreparator<? extends AbstractPacket> preparator =
                packet.getPacketPreparator(context.getChooser(), getEncryptor());
        preparator.prepare();
        AbstractPacketSerializer<? extends AbstractPacket> serializer =
                packet.getPacketSerializer();
        return serializer.serialize();
    }

    public void updateEncryptionCipher(PacketCipher encryptionCipher) {
        LOGGER.debug(
                "Activating new EncryptionCipher ("
                        + encryptionCipher.getClass().getSimpleName()
                        + ")");
        encryptor.addNewPacketCipher(encryptionCipher);
        writeEpoch++;
    }

    public void updateDecryptionCipher(PacketCipher decryptionCipher) {
        LOGGER.debug(
                "Activating new DecryptionCipher ("
                        + decryptionCipher.getClass().getSimpleName()
                        + ")");
        decryptor.addNewPacketCipher(decryptionCipher);
        readEpoch++;
    }

    public PacketCipher getEncryptorCipher() {
        return encryptor.getPacketMostRecentCipher();
    }

    public PacketCipher getDecryptorCipher() {
        return decryptor.getPacketMostRecentCipher();
    }

    public void resetEncryptor() {
        encryptor.removeAllCiphers();
    }

    public void resetDecryptor() {
        decryptor.removeAllCiphers();
    }

    public AbstractPacketEncryptor getEncryptor() {
        return encryptor;
    }

    public AbstractPacketDecryptor getDecryptor() {
        return decryptor;
    }

    public void increaseWriteEpoch() {
        writeEpoch++;
    }

    public int getWriteEpoch() {
        return writeEpoch;
    }

    public void setWriteEpoch(int writeEpoch) {
        this.writeEpoch = writeEpoch;
    }

    public void increaseReadEpoch() {
        readEpoch++;
    }

    public int getReadEpoch() {
        return readEpoch;
    }

    public void setReadEpoch(int readEpoch) {
        this.readEpoch = readEpoch;
    }
}
