/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

    private int writeEpoch = 0;
    private int readEpoch = 0;

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
                    // AbstractPacket packet = messageLayer.serialize(message);
                    Preparator preparator = packet.getPreparator(context);
                    preparator.prepare();
                    Serializer serializer = packet.getSerializer(context);
                    byte[] serializedMessage = serializer.serialize();

                    LayerProcessingResult layerProcessingResult =
                            getLowerLayer().sendData(null, serializedMessage);

                } catch (IOException e) {
                    LOGGER.warn("Error while sending packet: " + e.getMessage());
                    // return new LayerProcessingResult();
                }
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult<AbstractPacket> sendData(
            PacketLayerHint hint, byte[] additionalData) throws IOException {

        LOGGER.debug(
                "[bro] sending hint {} with data {}",
                hint.getType(),
                ArrayConverter.bytesToHexString(additionalData));
        MessageIdConstant type = MessageIdConstant.UNKNOWN;
        if (hint != null) {
            type = hint.getType();
        } else {
            LOGGER.warn(
                    "Sending record without a LayerProcessing hint. Using \"UNKNOWN\" as the type");
        }

        AbstractPacket packet;
        if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            LOGGER.debug("[bro] Created a BLOB Packet");
            packet = new BlobPacket();
        } else {
            LOGGER.debug("[bro] Created a Binary Packet");
            packet = new BinaryPacket();
        }
        packet.setPayload(additionalData);

        LOGGER.debug("[bro] Set Packetpayload");
        Preparator preparator = packet.getPreparator(context);
        LOGGER.debug("[bro] Got Preperator");
        preparator.prepare();
        LOGGER.debug("[bro] Prepared Packetpayload");
        Serializer serializer = packet.getSerializer(context);
        LOGGER.debug("[bro] got Serializier");
        byte[] serializedMessage = serializer.serialize();
        LOGGER.debug("[bro] Serializied Payload");

        List<AbstractPacket> packets = new LinkedList<>();
        packets.add(packet);

        getLowerLayer().sendData(null, serializedMessage);
        return new LayerProcessingResult<>(packets, getLayerType(), true);
    }

    @Override
    public LayerProcessingResult receiveData() {

        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        LOGGER.debug("[bro] receiveMoreDataForHint now in Transport");
        LayerProcessingHint desiredHint = hint;
        InputStream dataStream = getLowerLayer().getDataStream();
        LOGGER.debug("Avialble Data: {}", dataStream.available());
        AbstractPacketParser parser;
        AbstractPacket packet;

        LOGGER.debug("[bro] Recieving a {}", context.getPacketLayer());
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

        LOGGER.debug("[bro] Parsing a {}", context.getPacketLayer());
        parser.parse(packet);

        LOGGER.debug(
                "[bro] Recieved Packet: " + packet.getPayload() + " | " + packet.getCiphertext());

        context.getPacketLayer().getDecryptor().decrypt(packet);
        context.getPacketLayer().getDecompressor().decompress(packet);

        LOGGER.debug(
                "[bro] Decompressed Payload: {}",
                ArrayConverter.bytesToHexString(packet.getPayload()));

        packet.setPayload(packet.getPayload());

        addProducedContainer(packet);
        PacketLayerHint currentHint;

        /*        currentHint =
        new PacketLayerHint(
                MessageIdConstant.fromId(
                        packet.getPayload().getValue()[0], context.getContext()));*/
        currentHint = parseMessageId(packet, context);

        LOGGER.debug("[bro] got hint: " + currentHint.getType());

        if (desiredHint == null || currentHint.equals(desiredHint)) {
            if (currentInputStream == null) {
                // only set new input stream if necessary, extend current stream otherwise
                currentInputStream = new HintedLayerInputStream(currentHint, this);
            } else {
                currentInputStream.setHint(currentHint);
            }
            currentInputStream.extendStream(packet.getPayload().getValue());

        } else {

            if (nextInputStream == null) {
                // only set new input stream if necessary, extend current stream otherwise
                nextInputStream = new HintedLayerInputStream(currentHint, this);
            } else {
                nextInputStream.setHint(currentHint);
            }
            nextInputStream.extendStream(packet.getPayload().getValue());
        }
    }

    public PacketLayerHint parseMessageId(AbstractPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        if (packet instanceof BlobPacket) {
            String rawText = new String(packet.getPayload().getValue(), StandardCharsets.US_ASCII);
            if (rawText.startsWith("SSH-")) {
                return new PacketLayerHint(MessageIdConstant.VERSION_EXCHANGE_MESSAGE);
            } else {
                final AsciiMessage message = new AsciiMessage();
                AsciiMessageParser parser = new AsciiMessageParser(new ByteArrayInputStream(raw));
                parser.parse(message);

                // If we know what the text message means we can print a
                // human-readable warning to the log. The following
                // messages are sent by OpenSSH.
                final String messageText = message.getText().getValue();
                if ("Invalid SSH identification string.".equals(messageText)) {
                    LOGGER.warn(
                            "The server reported the identification string sent by the SSH-Attacker is invalid");
                } else if ("Exceeded MaxStartups".equals(messageText)) {
                    LOGGER.warn(
                            "The server reported the maximum number of concurrent unauthenticated connections has been exceeded.");
                }
                return new PacketLayerHint(MessageIdConstant.ASCII_MESSAGE);
            }
        }

        MessageIdConstant id =
                MessageIdConstant.fromId(packet.getPayload().getValue()[0], context.getContext());
        LOGGER.debug("[bro] Identifier: {} and constant {}", packet.getPayload().getValue()[0], id);

        switch (MessageIdConstant.fromId(packet.getPayload().getValue()[0], context.getContext())) {
            case SSH_MSG_DISCONNECT:
                LOGGER.debug("[bro] returning SSH_MSG_DISCONNECT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_DISCONNECT);
            case SSH_MSG_IGNORE:
                LOGGER.debug("[bro] returning SSH_MSG_IGNORE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_IGNORE);
            case SSH_MSG_UNIMPLEMENTED:
                LOGGER.debug("[bro] returning SSH_MSG_UNIMPLEMENTED Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_UNIMPLEMENTED);
            case SSH_MSG_DEBUG:
                LOGGER.debug("[bro] returning SSH_MSG_DEBUG Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_DEBUG);
            case SSH_MSG_SERVICE_ACCEPT:
                LOGGER.debug("[bro] returning SSH_MSG_SERVICE_ACCEPT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_SERVICE_ACCEPT);
            case SSH_MSG_EXT_INFO:
                LOGGER.debug("[bro] returning SSH_MSG_EXT_INFO Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_EXT_INFO);
            case SSH_MSG_NEWCOMPRESS:
                LOGGER.debug("[bro] returning SSH_MSG_NEWCOMPRESS Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_NEWCOMPRESS);
            case SSH_MSG_KEXINIT:
                LOGGER.debug("[bro] returning SSH KEX INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXINIT);
            case SSH_MSG_NEWKEYS:
                LOGGER.debug("[bro] returning SSH_MSG_NEWKEYS Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_NEWKEYS);
            case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_DH_GEX_REQUEST_OLD Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
            case SSH_MSG_KEX_DH_GEX_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_DH_GEX_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST);
            case SSH_MSG_KEX_DH_GEX_GROUP:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_DH_GEX_GROUP Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_DH_GEX_GROUP);
            case SSH_MSG_KEX_DH_GEX_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_DH_GEX_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_DH_GEX_INIT);
            case SSH_MSG_KEX_DH_GEX_REPLY:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_DH_GEX_REPLY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REPLY);
            case SSH_MSG_KEXDH_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_KEXDH_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXDH_INIT);
            case SSH_MSG_KEXDH_REPLY:
                LOGGER.debug("[bro] returning SSH_MSG_KEXDH_REPLY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXDH_REPLY);
            case SSH_MSG_HBR_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_HBR_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_HBR_INIT);
            case SSH_MSG_HBR_REPLY:
                LOGGER.debug("[bro] returning SSH_MSG_HBR_REPLY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_HBR_REPLY);
            case SSH_MSG_SERVICE_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_SERVICE_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_SERVICE_REQUEST);
            case SSH_MSG_KEX_ECDH_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_ECDH_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_ECDH_INIT);
            case SSH_MSG_KEX_ECDH_REPLY:
                LOGGER.debug("[bro] returning SSH_MSG_KEX_ECDH_REPLY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEX_ECDH_REPLY);
            case SSH_MSG_ECMQV_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_ECMQV_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_ECMQV_INIT);
            case SSH_MSG_ECMQV_REPLY:
                LOGGER.debug("[bro] returning SSH_MSG_ECMQV_REPLY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_ECMQV_REPLY);
            case SSH_MSG_KEXRSA_PUBKEY:
                LOGGER.debug("[bro] returning SSH_MSG_KEXRSA_PUBKEY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXRSA_PUBKEY);
            case SSH_MSG_KEXRSA_SECRET:
                LOGGER.debug("[bro] returning SSH_MSG_KEXRSA_SECRET Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXRSA_SECRET);
            case SSH_MSG_KEXRSA_DONE:
                LOGGER.debug("[bro] returning SSH_MSG_KEXRSA_DONE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXRSA_DONE);
            case SSH_MSG_KEXGSS_INIT:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_INIT Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_INIT);
            case SSH_MSG_KEXGSS_CONTINUE:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_CONTINUE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_CONTINUE);
            case SSH_MSG_KEXGSS_COMPLETE:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_COMPLETE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_COMPLETE);
            case SSH_MSG_KEXGSS_HOSTKEY:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_HOSTKEY Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_HOSTKEY);
            case SSH_MSG_KEXGSS_ERROR:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_ERROR Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_ERROR);
            case SSH_MSG_KEXGSS_GROUPREQ:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_GROUPREQ Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_GROUPREQ);
            case SSH_MSG_KEXGSS_GROUP:
                LOGGER.debug("[bro] returning SSH_MSG_KEXGSS_GROUP Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_KEXGSS_GROUP);
            case SSH_MSG_USERAUTH_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_REQUEST);
            case SSH_MSG_USERAUTH_FAILURE:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_FAILURE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_FAILURE);
            case SSH_MSG_USERAUTH_SUCCESS:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_SUCCESS Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_SUCCESS);
            case SSH_MSG_USERAUTH_BANNER:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_BANNER Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_BANNER);
            case SSH_MSG_USERAUTH_PK_OK:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_PK_OK Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_PK_OK);
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_PASSWD_CHANGEREQ Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ);
            case SSH_MSG_USERAUTH_INFO_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_INFO_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_INFO_REQUEST);
            case SSH_MSG_USERAUTH_INFO_RESPONSE:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_INFO_RESPONSE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_INFO_RESPONSE);
            case SSH_MSG_USERAUTH_GSSAPI_RESPONSE:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_RESPONSE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_RESPONSE);
            case SSH_MSG_USERAUTH_GSSAPI_TOKEN:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_TOKEN Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_TOKEN);
            case SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE Hint");
                return new PacketLayerHint(
                        MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE);
            case SSH_MSG_USERAUTH_GSSAPI_ERROR:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_ERROR Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_ERROR);
            case SSH_MSG_USERAUTH_GSSAPI_ERRTOK:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_ERRTOK Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_ERRTOK);
            case SSH_MSG_USERAUTH_GSSAPI_MIC:
                LOGGER.debug("[bro] returning SSH_MSG_USERAUTH_GSSAPI_MIC Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_USERAUTH_GSSAPI_MIC);
            case SSH_MSG_GLOBAL_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_GLOBAL_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_GLOBAL_REQUEST);
            case SSH_MSG_REQUEST_SUCCESS:
                LOGGER.debug("[bro] returning SSH_MSG_REQUEST_SUCCESS Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_REQUEST_SUCCESS);
            case SSH_MSG_REQUEST_FAILURE:
                LOGGER.debug("[bro] returning SSH_MSG_REQUEST_FAILURE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_REQUEST_FAILURE);
            case SSH_MSG_CHANNEL_OPEN:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_OPEN Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_OPEN);
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_OPEN_CONFIRMATION Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_OPEN_FAILURE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_OPEN_FAILURE);
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_WINDOW_ADJUST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST);
            case SSH_MSG_CHANNEL_DATA:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_DATA Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_DATA);
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_EXTENDED_DATA Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_EXTENDED_DATA);
            case SSH_MSG_CHANNEL_EOF:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_EOF Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_EOF);
            case SSH_MSG_CHANNEL_CLOSE:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_CLOSE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_CLOSE);
            case SSH_MSG_CHANNEL_REQUEST:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_REQUEST Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_REQUEST);
            case SSH_MSG_CHANNEL_SUCCESS:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_SUCCESS Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_SUCCESS);
            case SSH_MSG_CHANNEL_FAILURE:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_FAILURE Hint");
                return new PacketLayerHint(MessageIdConstant.SSH_MSG_CHANNEL_FAILURE);
            case UNKNOWN:
                LOGGER.debug("[bro] returning UNKNOWN Hint");
                return new PacketLayerHint(MessageIdConstant.UNKNOWN);
            default:
                LOGGER.debug(
                        "[bro] cannot identifie {} as {} - returningn null",
                        raw[1],
                        MessageIdConstant.fromId(
                                packet.getPayload().getValue()[0], context.getContext()));
                return null;
        }
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

    protected void decryptPacket(AbstractPacket<?> packet) {
        packet.prepareComputations();
        getDecryptor().decrypt(packet);
    }
}
