/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeInitConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageParser extends SshMessageParser<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public KeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public KeyExchangeInitMessage createMessage() {
        return new KeyExchangeInitMessage();
    }

    private void parseCookie() {
        message.setCookie(parseByteArrayField(KeyExchangeInitConstants.COOKIE_LENGTH));
        LOGGER.debug("Cookie: {}", message.getCookie());
    }

    private void parseKeyExchangeAlgorithms() {
        int keyExchangeAlgorithmsLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setKeyExchangeAlgorithmsLength(keyExchangeAlgorithmsLength);
        LOGGER.debug("Key exchange algorithms length: {}", keyExchangeAlgorithmsLength);
        String keyExchangeAlgorithms =
                parseByteString(keyExchangeAlgorithmsLength, StandardCharsets.US_ASCII);
        message.setKeyExchangeAlgorithms(keyExchangeAlgorithms);
        LOGGER.debug(
                "Key exchange algorithms: {}", () -> backslashEscapeString(keyExchangeAlgorithms));
    }

    private void parseServerHostKeyAlgorithms() {
        int serverHostKeyAlgorithmsLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setServerHostKeyAlgorithmsLength(serverHostKeyAlgorithmsLength);
        LOGGER.debug("Server host key algorithms length: {}", serverHostKeyAlgorithmsLength);
        String serverHostKeyAlgorithms =
                parseByteString(serverHostKeyAlgorithmsLength, StandardCharsets.US_ASCII);
        message.setServerHostKeyAlgorithms(serverHostKeyAlgorithms);
        LOGGER.debug(
                "Server host key algorithms: {}",
                () -> backslashEscapeString(serverHostKeyAlgorithms));
    }

    private void parseEncryptionAlgorithmsClientToServer() {
        int encryptionAlgorithmsClientToServerLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setEncryptionAlgorithmsClientToServerLength(
                encryptionAlgorithmsClientToServerLength);
        LOGGER.debug(
                "Encryption algorithms length (client to server): {}",
                encryptionAlgorithmsClientToServerLength);
        String encryptionAlgorithmsClientToServer =
                parseByteString(
                        encryptionAlgorithmsClientToServerLength, StandardCharsets.US_ASCII);
        message.setEncryptionAlgorithmsClientToServer(encryptionAlgorithmsClientToServer);
        LOGGER.debug(
                "Encryption algorithms (client to server): {}",
                () -> backslashEscapeString(encryptionAlgorithmsClientToServer));
    }

    private void parseEncryptionAlgorithmsServerToClient() {
        int encryptionAlgorithmsServerToClientLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setEncryptionAlgorithmsServerToClientLength(
                encryptionAlgorithmsServerToClientLength);
        LOGGER.debug(
                "Encryption algorithms length (server to client): {}",
                encryptionAlgorithmsServerToClientLength);
        String encryptionAlgorithmsServerToClient =
                parseByteString(
                        encryptionAlgorithmsServerToClientLength, StandardCharsets.US_ASCII);
        message.setEncryptionAlgorithmsServerToClient(encryptionAlgorithmsServerToClient);
        LOGGER.debug(
                "Encryption algorithms (server to client): {}",
                () -> backslashEscapeString(encryptionAlgorithmsServerToClient));
    }

    private void parseMacAlgorithmsClientToServer() {
        int macAlgorithmsClientToServerLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setMacAlgorithmsClientToServerLength(macAlgorithmsClientToServerLength);
        LOGGER.debug(
                "MAC algorithms length (client to server): {}", macAlgorithmsClientToServerLength);
        String macAlgorithmsClientToServer =
                parseByteString(macAlgorithmsClientToServerLength, StandardCharsets.US_ASCII);
        message.setMacAlgorithmsClientToServer(macAlgorithmsClientToServer);
        LOGGER.debug(
                "MAC algorithms (client to server): {}",
                () -> backslashEscapeString(macAlgorithmsClientToServer));
    }

    private void parseMacAlgorithmsServerToClient() {
        int macAlgorithmsServerToClientLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setMacAlgorithmsServerToClientLength(macAlgorithmsServerToClientLength);
        LOGGER.debug(
                "MAC algorithms length (server to client): {}", macAlgorithmsServerToClientLength);
        String macAlgorithmsServerToClient =
                parseByteString(macAlgorithmsServerToClientLength, StandardCharsets.US_ASCII);
        message.setMacAlgorithmsServerToClient(macAlgorithmsServerToClient);
        LOGGER.debug(
                "MAC algorithms (server to client): {}",
                () -> backslashEscapeString(macAlgorithmsServerToClient));
    }

    private void parseCompressionMethodsClientToServer() {
        int compressionMethodsClientToServerLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setCompressionMethodsClientToServerLength(compressionMethodsClientToServerLength);
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        String compressionMethodsClientToServer =
                parseByteString(compressionMethodsClientToServerLength, StandardCharsets.US_ASCII);
        message.setCompressionMethodsClientToServer(compressionMethodsClientToServer);
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                () -> backslashEscapeString(compressionMethodsClientToServer));
    }

    private void parseCompressionMethodsServerToClient() {
        int compressionMethodsServerToClientLength =
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setCompressionMethodsServerToClientLength(compressionMethodsServerToClientLength);
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        String compressionMethodsServerToClient =
                parseByteString(compressionMethodsServerToClientLength, StandardCharsets.US_ASCII);
        message.setCompressionMethodsServerToClient(compressionMethodsServerToClient);
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                () -> backslashEscapeString(compressionMethodsServerToClient));
    }

    private void parseLanguagesClientToServer() {
        int languagesClientToServerLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguagesClientToServerLength(languagesClientToServerLength);
        LOGGER.debug("Languages length (client to server): {}", languagesClientToServerLength);
        String languagesClientToServer =
                parseByteString(languagesClientToServerLength, StandardCharsets.US_ASCII);
        message.setLanguagesClientToServer(languagesClientToServer);
        LOGGER.debug(
                "Languages (client to server): {}",
                () -> backslashEscapeString(languagesClientToServer));
    }

    private void parseLanguagesServerToClient() {
        int languagesServerToClientLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguagesServerToClientLength(languagesServerToClientLength);
        LOGGER.debug("Languages length (server to client): {}", languagesServerToClientLength);
        String languagesServerToClient =
                parseByteString(languagesServerToClientLength, StandardCharsets.US_ASCII);
        message.setLanguagesServerToClient(languagesServerToClient);
        LOGGER.debug(
                "Languages (server to client): {}",
                () -> backslashEscapeString(languagesServerToClient));
    }

    private void parseFirstKeyExchangePacketFollows() {
        byte firstKeyExchangePacketFollows = parseByteField(1);
        message.setFirstKeyExchangePacketFollows(firstKeyExchangePacketFollows);
        LOGGER.debug(
                "First key exchange packet follows: {}",
                Converter.byteToBoolean(firstKeyExchangePacketFollows));
    }

    private void parseReserved() {
        int reserved = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setReserved(reserved);
        LOGGER.debug("Reserved: {}", reserved);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseCookie();
        parseKeyExchangeAlgorithms();
        parseServerHostKeyAlgorithms();
        parseEncryptionAlgorithmsClientToServer();
        parseEncryptionAlgorithmsServerToClient();
        parseMacAlgorithmsClientToServer();
        parseMacAlgorithmsServerToClient();
        parseCompressionMethodsClientToServer();
        parseCompressionMethodsServerToClient();
        parseLanguagesClientToServer();
        parseLanguagesServerToClient();
        parseFirstKeyExchangePacketFollows();
        parseReserved();
    }
}
