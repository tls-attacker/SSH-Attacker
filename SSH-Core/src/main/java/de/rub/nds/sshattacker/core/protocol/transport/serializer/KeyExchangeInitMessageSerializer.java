/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageSerializer extends SshMessageSerializer<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageSerializer(KeyExchangeInitMessage message) {
        super(message);
    }

    private void serializeCookie() {
        LOGGER.debug("Cookie: " + message.getCookie());
        appendBytes(message.getCookie().getValue());
    }

    private void serializeKeyExchangeAlgorithms() {
        LOGGER.debug(
                "Key exchange algorithms: " + message.getKeyExchangeAlgorithmsLength().getValue());
        appendInt(
                message.getKeyExchangeAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Key exchange algorithms: " + message.getKeyExchangeAlgorithms().getValue());
        appendString(message.getKeyExchangeAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeServerHostKeyAlgorithms() {
        LOGGER.debug(
                "Server host key algorithms: "
                        + message.getServerHostKeyAlgorithmsLength().getValue());
        appendInt(
                message.getServerHostKeyAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Server host key algorithms: " + message.getServerHostKeyAlgorithms().getValue());
        appendString(message.getServerHostKeyAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsClientToServer() {
        LOGGER.debug(
                "Encryption algorithms length (client to server): "
                        + message.getEncryptionAlgorithmsClientToServerLength().getValue());
        appendInt(
                message.getEncryptionAlgorithmsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Encryption algorithms (client to server): "
                        + message.getEncryptionAlgorithmsClientToServer().getValue());
        appendString(
                message.getEncryptionAlgorithmsClientToServer().getValue(),
                StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsServerToClient() {
        LOGGER.debug(
                "Encryption algorithms length (server to client): "
                        + message.getEncryptionAlgorithmsServerToClientLength().getValue());
        appendInt(
                message.getEncryptionAlgorithmsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Encryption algorithms (server to client): "
                        + message.getEncryptionAlgorithmsServerToClient().getValue());
        appendString(
                message.getEncryptionAlgorithmsServerToClient().getValue(),
                StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsClientToServer() {
        LOGGER.debug(
                "MAC algorithms length (client to server): "
                        + message.getMacAlgorithmsClientToServerLength().getValue());
        appendInt(
                message.getMacAlgorithmsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "MAC algorithms (client to server): "
                        + message.getMacAlgorithmsClientToServer().getValue());
        appendString(
                message.getMacAlgorithmsClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsServerToClient() {
        LOGGER.debug(
                "MAC algorithms length (server to client): "
                        + message.getMacAlgorithmsServerToClientLength().getValue());
        appendInt(
                message.getMacAlgorithmsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "MAC algorithms (server to client): "
                        + message.getMacAlgorithmsServerToClient().getValue());
        appendString(
                message.getMacAlgorithmsServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeCompressionMethodsClientToServer() {
        LOGGER.debug(
                "Compression algorithms length (client to server): "
                        + message.getCompressionMethodsClientToServerLength().getValue());
        appendInt(
                message.getCompressionMethodsClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (client to server): "
                        + message.getCompressionMethodsClientToServer().getValue());
        appendString(
                message.getCompressionMethodsClientToServer().getValue(),
                StandardCharsets.US_ASCII);
    }

    private void serializeCompressionMethodsServerToClient() {
        LOGGER.debug(
                "Compression algorithms length (server to client): "
                        + message.getCompressionMethodsServerToClientLength().getValue());
        appendInt(
                message.getCompressionMethodsServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (server to client): "
                        + message.getCompressionMethodsServerToClient().getValue());
        appendString(
                message.getCompressionMethodsServerToClient().getValue(),
                StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesClientToServer() {
        LOGGER.debug(
                "Languages length (client to server): "
                        + message.getLanguagesClientToServerLength().getValue());
        appendInt(
                message.getLanguagesClientToServerLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Languages (client to server): " + message.getLanguagesClientToServer().getValue());
        appendString(message.getLanguagesClientToServer().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesServerToClient() {
        LOGGER.debug(
                "Languages length (server to client): "
                        + message.getLanguagesServerToClientLength().getValue());
        appendInt(
                message.getLanguagesServerToClientLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Languages (server to client): " + message.getLanguagesServerToClient().getValue());
        appendString(message.getLanguagesServerToClient().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeFirstKeyExchangePacketFollows() {
        LOGGER.debug(
                "First key exchange packet follows: "
                        + Converter.byteToBoolean(
                                message.getFirstKeyExchangePacketFollows().getValue()));
        appendByte(message.getFirstKeyExchangePacketFollows().getValue());
    }

    private void serializeReserved() {
        LOGGER.debug("Reserved: " + message.getReserved().getValue());
        appendInt(message.getReserved().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeCookie();
        serializeKeyExchangeAlgorithms();
        serializeServerHostKeyAlgorithms();
        serializeEncryptionAlgorithmsClientToServer();
        serializeEncryptionAlgorithmsServerToClient();
        serializeMacAlgorithmsClientToServer();
        serializeMacAlgorithmsServerToClient();
        serializeCompressionMethodsClientToServer();
        serializeCompressionMethodsServerToClient();
        serializeLanguagesClientToServer();
        serializeLanguagesServerToClient();
        serializeFirstKeyExchangePacketFollows();
        serializeReserved();
    }
}
