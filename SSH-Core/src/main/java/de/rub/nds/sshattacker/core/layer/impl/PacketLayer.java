/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

import de.rub.nds.sshattacker.core.constants.CipherMode;
import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerProcessingResult;
import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Preparator;
import de.rub.nds.sshattacker.core.layer.data.Serializer;
import de.rub.nds.sshattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.sshattacker.core.layer.hints.PacketLayerHint;
import de.rub.nds.sshattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.compressor.PacketCompressor;
import de.rub.nds.sshattacker.core.packet.compressor.PacketDecompressor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketDecryptor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.packet.crypto.PacketDecryptor;
import de.rub.nds.sshattacker.core.packet.crypto.PacketEncryptor;
import de.rub.nds.sshattacker.core.packet.parser.AbstractPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketLayer extends ProtocolLayer<PacketLayerHint, AbstractPacket> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    private final AbstractPacketDecryptor decryptor;
    private final AbstractPacketEncryptor encryptor;

    private final PacketCompressor compressor;
    private final PacketDecompressor decompressor;

    public PacketLayer(SshContext context) {
        super(ImplementedLayers.PACKET_LAYER);
        this.context = context;
        encryptor =
                new PacketEncryptor(
                        PacketCipherFactory.getNoneCipher(context, CipherMode.ENCRYPT), context);
        decryptor =
                new PacketDecryptor(
                        PacketCipherFactory.getNoneCipher(context, CipherMode.DECRYPT), context);
        compressor = new PacketCompressor();
        decompressor = new PacketDecompressor();
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {

        LayerConfiguration<AbstractPacket> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (AbstractPacket packet : configuration.getContainerList()) {
                if (containerAlreadyUsedByHigherLayer(packet) /*|| skipEmptyRecords(session)*/) {
                    continue;
                }

                try {
                    Preparator preparator = packet.getPreparator(context);
                    preparator.prepare();
                    Serializer serializer = packet.getSerializer(context);
                    byte[] serializedMessage = serializer.serialize();

                    LayerProcessingResult layerProcessingResult =
                            getLowerLayer().sendData(serializedMessage);

                } catch (IOException e) {
                    LOGGER.warn("Error while sending packet: " + e.getMessage());
                }
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult<AbstractPacket> sendData(byte[] additionalData)
            throws IOException {

        MessageIdConstant type = MessageIdConstant.UNKNOWN;

        AbstractPacket packet;
        if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            packet = new BlobPacket();
        } else {
            packet = new BinaryPacket();
        }
        packet.setPayload(additionalData);

        Preparator preparator = packet.getPreparator(context);
        preparator.prepare();
        Serializer serializer = packet.getSerializer(context);
        byte[] serializedMessage = serializer.serialize();

        List<AbstractPacket> packets = new LinkedList<>();
        packets.add(packet);

        getLowerLayer().sendData(serializedMessage);
        return new LayerProcessingResult<>(packets, getLayerType(), true);
    }

    @Override
    public LayerProcessingResult receiveData() {

        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        LayerProcessingHint desiredHint = hint;
        InputStream dataStream = getLowerLayer().getDataStream();
        /*LOGGER.debug("Avialble Data: {}", dataStream.available());*/
        AbstractPacketParser parser;
        AbstractPacket packet;

        if (context.getPacketLayerType() == PacketLayerType.BINARY_PACKET) {
            parser =
                    new BinaryPacketParser(
                            dataStream,
                            context.getPacketLayer().getDecryptorCipher(),
                            context.getReadSequenceNumber());
            packet = new BinaryPacket();
        } else if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            parser = new BlobPacketParser(dataStream);
            packet = new BlobPacket();
        } else {
            throw new RuntimeException();
        }

        parser.parse(packet);

        /*LOGGER.debug(
                        "[bro] Recieved Packet: " + packet.getPayload() + " | " + packet.getCiphertext());
        */
        context.getPacketLayer().getDecryptor().decrypt(packet);
        context.getPacketLayer().getDecompressor().decompress(packet);

        /*LOGGER.debug(
        "[bro] Decompressed Payload: {}",
        ArrayConverter.bytesToHexString(packet.getPayload()));*/

        addProducedContainer(packet);

        if (currentInputStream == null) {
            // only set new input stream if necessary, extend current stream otherwise
            currentInputStream = new HintedLayerInputStream(null, this);
        } else {
            currentInputStream.setHint(null);
        }
        currentInputStream.extendStream(packet.getPayload().getValue());
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

    public PacketCompressor getCompressor() {
        return compressor;
    }

    public PacketDecompressor getDecompressor() {
        return decompressor;
    }

    public void updateCompressionAlgorithm(CompressionAlgorithm algorithm) {
        compressor.setCompressionAlgorithm(algorithm);
    }

    public void updateDecompressionAlgorithm(CompressionAlgorithm algorithm) {
        decompressor.setCompressionAlgorithm(algorithm);
    }

    public void updateEncryptionCipher(PacketCipher encryptionCipher) {
        LOGGER.debug(
                "Activating new EncryptionCipher ("
                        + encryptionCipher.getClass().getSimpleName()
                        + ")");
        encryptor.addNewPacketCipher(encryptionCipher);
    }

    public void updateDecryptionCipher(PacketCipher decryptionCipher) {
        LOGGER.debug(
                "Activating new DecryptionCipher ("
                        + decryptionCipher.getClass().getSimpleName()
                        + ")");
        decryptor.addNewPacketCipher(decryptionCipher);
    }

    protected void decryptPacket(AbstractPacket<?> packet) {
        packet.prepareComputations();
        getDecryptor().decrypt(packet);
    }
}
