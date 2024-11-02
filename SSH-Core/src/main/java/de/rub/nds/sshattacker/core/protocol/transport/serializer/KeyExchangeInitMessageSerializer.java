/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

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
        LOGGER.debug("Cookie: {}", message.getCookie());
        appendBytes(message.getCookie().getValue());
    }

    private void serializeKeyExchangeAlgorithms() {
        Integer keyExchangeAlgorithmsLength = message.getKeyExchangeAlgorithmsLength().getValue();
        LOGGER.debug("Key exchange algorithms: {}", keyExchangeAlgorithmsLength);
        appendInt(keyExchangeAlgorithmsLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String keyExchangeAlgorithms = message.getKeyExchangeAlgorithms().getValue();
        LOGGER.debug(
                "Key exchange algorithms: {}", () -> backslashEscapeString(keyExchangeAlgorithms));
        appendString(keyExchangeAlgorithms, StandardCharsets.US_ASCII);
    }

    private void serializeServerHostKeyAlgorithms() {
        Integer serverHostKeyAlgorithmsLength =
                message.getServerHostKeyAlgorithmsLength().getValue();
        LOGGER.debug("Server host key algorithms: {}", serverHostKeyAlgorithmsLength);
        appendInt(serverHostKeyAlgorithmsLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String serverHostKeyAlgorithms = message.getServerHostKeyAlgorithms().getValue();
        LOGGER.debug(
                "Server host key algorithms: {}",
                () -> backslashEscapeString(serverHostKeyAlgorithms));
        appendString(serverHostKeyAlgorithms, StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsClientToServer() {
        Integer encryptionAlgorithmsClientToServerLength =
                message.getEncryptionAlgorithmsClientToServerLength().getValue();
        LOGGER.debug(
                "Encryption algorithms length (client to server): {}",
                encryptionAlgorithmsClientToServerLength);
        appendInt(encryptionAlgorithmsClientToServerLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String encryptionAlgorithmsClientToServer =
                message.getEncryptionAlgorithmsClientToServer().getValue();
        LOGGER.debug(
                "Encryption algorithms (client to server): {}",
                () -> backslashEscapeString(encryptionAlgorithmsClientToServer));
        appendString(encryptionAlgorithmsClientToServer, StandardCharsets.US_ASCII);
    }

    private void serializeEncryptionAlgorithmsServerToClient() {
        Integer encryptionAlgorithmsServerToClientLength =
                message.getEncryptionAlgorithmsServerToClientLength().getValue();
        LOGGER.debug(
                "Encryption algorithms length (server to client): {}",
                encryptionAlgorithmsServerToClientLength);
        appendInt(encryptionAlgorithmsServerToClientLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String encryptionAlgorithmsServerToClient =
                message.getEncryptionAlgorithmsServerToClient().getValue();
        LOGGER.debug(
                "Encryption algorithms (server to client): {}",
                () -> backslashEscapeString(encryptionAlgorithmsServerToClient));
        appendString(encryptionAlgorithmsServerToClient, StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsClientToServer() {
        Integer macAlgorithmsClientToServerLength =
                message.getMacAlgorithmsClientToServerLength().getValue();
        LOGGER.debug(
                "MAC algorithms length (client to server): {}", macAlgorithmsClientToServerLength);
        appendInt(macAlgorithmsClientToServerLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String macAlgorithmsClientToServer = message.getMacAlgorithmsClientToServer().getValue();
        LOGGER.debug(
                "MAC algorithms (client to server): {}",
                () -> backslashEscapeString(macAlgorithmsClientToServer));
        appendString(macAlgorithmsClientToServer, StandardCharsets.US_ASCII);
    }

    private void serializeMacAlgorithmsServerToClient() {
        Integer macAlgorithmsServerToClientLength =
                message.getMacAlgorithmsServerToClientLength().getValue();
        LOGGER.debug(
                "MAC algorithms length (server to client): {}", macAlgorithmsServerToClientLength);
        appendInt(macAlgorithmsServerToClientLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String macAlgorithmsServerToClient = message.getMacAlgorithmsServerToClient().getValue();
        LOGGER.debug(
                "MAC algorithms (server to client): {}",
                () -> backslashEscapeString(macAlgorithmsServerToClient));
        appendString(macAlgorithmsServerToClient, StandardCharsets.US_ASCII);
    }

    private void serializeCompressionMethodsClientToServer() {
        Integer compressionMethodsClientToServerLength =
                message.getCompressionMethodsClientToServerLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        appendInt(compressionMethodsClientToServerLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String compressionMethodsClientToServer =
                message.getCompressionMethodsClientToServer().getValue();
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                () -> backslashEscapeString(compressionMethodsClientToServer));
        appendString(compressionMethodsClientToServer, StandardCharsets.US_ASCII);
    }

    private void serializeCompressionMethodsServerToClient() {
        Integer compressionMethodsServerToClientLength =
                message.getCompressionMethodsServerToClientLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        appendInt(compressionMethodsServerToClientLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String compressionMethodsServerToClient =
                message.getCompressionMethodsServerToClient().getValue();
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                () -> backslashEscapeString(compressionMethodsServerToClient));
        appendString(compressionMethodsServerToClient, StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesClientToServer() {
        Integer languagesClientToServerLength =
                message.getLanguagesClientToServerLength().getValue();
        LOGGER.debug("Languages length (client to server): {}", languagesClientToServerLength);
        appendInt(languagesClientToServerLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languagesClientToServer = message.getLanguagesClientToServer().getValue();
        LOGGER.debug(
                "Languages (client to server): {}",
                () -> backslashEscapeString(languagesClientToServer));
        appendString(languagesClientToServer, StandardCharsets.US_ASCII);
    }

    private void serializeLanguagesServerToClient() {
        Integer languagesServerToClientLength =
                message.getLanguagesServerToClientLength().getValue();
        LOGGER.debug("Languages length (server to client): {}", languagesServerToClientLength);
        appendInt(languagesServerToClientLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languagesServerToClient = message.getLanguagesServerToClient().getValue();
        LOGGER.debug(
                "Languages (server to client): {}",
                () -> backslashEscapeString(languagesServerToClient));
        appendString(languagesServerToClient, StandardCharsets.US_ASCII);
    }

    private void serializeFirstKeyExchangePacketFollows() {
        Byte firstKeyExchangePacketFollows = message.getFirstKeyExchangePacketFollows().getValue();
        LOGGER.debug(
                "First key exchange packet follows: {}",
                () -> Converter.byteToBoolean(firstKeyExchangePacketFollows));
        appendByte(firstKeyExchangePacketFollows);
    }

    private void serializeReserved() {
        Integer reserved = message.getReserved().getValue();
        LOGGER.debug("Reserved: {}", reserved);
        appendInt(reserved, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
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
