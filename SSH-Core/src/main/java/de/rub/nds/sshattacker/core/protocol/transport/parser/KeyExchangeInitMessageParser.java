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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageParser extends SshMessageParser<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseCookie(KeyExchangeInitMessage message) {
        message.setCookie(parseByteArrayField(KeyExchangeInitConstants.COOKIE_LENGTH));
        LOGGER.debug("Cookie: {}", message.getCookie());
    }

    private void parseKeyExchangeAlgorithms(KeyExchangeInitMessage message) {
        message.setKeyExchangeAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Key exchange algorithms length: {}",
                message.getKeyExchangeAlgorithmsLength().getValue());
        message.setKeyExchangeAlgorithms(
                parseByteString(
                        message.getKeyExchangeAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Key exchange algorithms: {}",
                backslashEscapeString(message.getKeyExchangeAlgorithms().getValue()));
    }

    private void parseServerHostKeyAlgorithms(KeyExchangeInitMessage message) {
        message.setServerHostKeyAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Server host key algorithms length: {}",
                message.getServerHostKeyAlgorithmsLength().getValue());
        message.setServerHostKeyAlgorithms(
                parseByteString(
                        message.getServerHostKeyAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Server host key algorithms: {}",
                backslashEscapeString(message.getServerHostKeyAlgorithms().getValue()));
    }

    private void parseEncryptionAlgorithmsClientToServer(KeyExchangeInitMessage message) {
        message.setEncryptionAlgorithmsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Encryption algorithms length (client to server): {}",
                message.getEncryptionAlgorithmsClientToServerLength().getValue());
        message.setEncryptionAlgorithmsClientToServer(
                parseByteString(
                        message.getEncryptionAlgorithmsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Encryption algorithms (client to server): {}",
                backslashEscapeString(message.getEncryptionAlgorithmsClientToServer().getValue()));
    }

    private void parseEncryptionAlgorithmsServerToClient(KeyExchangeInitMessage message) {
        message.setEncryptionAlgorithmsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Encryption algorithms length (server to client): {}",
                message.getEncryptionAlgorithmsServerToClientLength().getValue());
        message.setEncryptionAlgorithmsServerToClient(
                parseByteString(
                        message.getEncryptionAlgorithmsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Encryption algorithms (server to client): {}",
                backslashEscapeString(message.getEncryptionAlgorithmsServerToClient().getValue()));
    }

    private void parseMacAlgorithmsClientToServer(KeyExchangeInitMessage message) {
        message.setMacAlgorithmsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "MAC algorithms length (client to server): {}",
                message.getMacAlgorithmsClientToServerLength().getValue());
        message.setMacAlgorithmsClientToServer(
                parseByteString(
                        message.getMacAlgorithmsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "MAC algorithms (client to server): {}",
                backslashEscapeString(message.getMacAlgorithmsClientToServer().getValue()));
    }

    private void parseMacAlgorithmsServerToClient(KeyExchangeInitMessage message) {
        message.setMacAlgorithmsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "MAC algorithms length (server to client): {}",
                message.getMacAlgorithmsServerToClientLength().getValue());
        message.setMacAlgorithmsServerToClient(
                parseByteString(
                        message.getMacAlgorithmsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "MAC algorithms (server to client): {}",
                backslashEscapeString(message.getMacAlgorithmsServerToClient().getValue()));
    }

    private void parseCompressionMethodsClientToServer(KeyExchangeInitMessage message) {
        message.setCompressionMethodsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                message.getCompressionMethodsClientToServerLength().getValue());
        message.setCompressionMethodsClientToServer(
                parseByteString(
                        message.getCompressionMethodsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                backslashEscapeString(message.getCompressionMethodsClientToServer().getValue()));
    }

    private void parseCompressionMethodsServerToClient(KeyExchangeInitMessage message) {
        message.setCompressionMethodsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                message.getCompressionMethodsServerToClientLength().getValue());
        message.setCompressionMethodsServerToClient(
                parseByteString(
                        message.getCompressionMethodsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                backslashEscapeString(message.getCompressionMethodsServerToClient().getValue()));
    }

    private void parseLanguagesClientToServer(KeyExchangeInitMessage message) {
        message.setLanguagesClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Languages length (client to server): {}",
                message.getLanguagesClientToServerLength().getValue());
        message.setLanguagesClientToServer(
                parseByteString(
                        message.getLanguagesClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Languages (client to server): {}",
                backslashEscapeString(message.getLanguagesClientToServer().getValue()));
    }

    private void parseLanguagesServerToClient(KeyExchangeInitMessage message) {
        message.setLanguagesServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Languages length (server to client): {}",
                message.getLanguagesServerToClientLength().getValue());
        message.setLanguagesServerToClient(
                parseByteString(
                        message.getLanguagesServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Languages (server to client): {}",
                backslashEscapeString(message.getLanguagesServerToClient().getValue()));
    }

    private void parseFirstKeyExchangePacketFollows(KeyExchangeInitMessage message) {
        message.setFirstKeyExchangePacketFollows(parseByteField(1));
        LOGGER.debug(
                "First key exchange packet follows: {}",
                Converter.byteToBoolean(message.getFirstKeyExchangePacketFollows().getValue()));
    }

    private void parseReserved(KeyExchangeInitMessage message) {
        message.setReserved(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Reserved: {}", message.getReserved().getValue());
    }

    @Override
    public void parseMessageSpecificContents(KeyExchangeInitMessage message) {
        parseCookie(message);
        parseKeyExchangeAlgorithms(message);
        parseServerHostKeyAlgorithms(message);
        parseEncryptionAlgorithmsClientToServer(message);
        parseEncryptionAlgorithmsServerToClient(message);
        parseMacAlgorithmsClientToServer(message);
        parseMacAlgorithmsServerToClient(message);
        parseCompressionMethodsClientToServer(message);
        parseCompressionMethodsServerToClient(message);
        parseLanguagesClientToServer(message);
        parseLanguagesServerToClient(message);
        parseFirstKeyExchangePacketFollows(message);
        parseReserved(message);
    }

    @Override
    public void parse(KeyExchangeInitMessage message) {
        parseProtocolMessageContents(message);
    }
}
