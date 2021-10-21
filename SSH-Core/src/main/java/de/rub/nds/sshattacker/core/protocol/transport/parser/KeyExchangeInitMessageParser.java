/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

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

    public KeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public KeyExchangeInitMessage createMessage() {
        return new KeyExchangeInitMessage();
    }

    private void parseCookie() {
        message.setCookie(parseByteArrayField(KeyExchangeInitConstants.COOKIE_LENGTH));
        LOGGER.debug("Cookie: " + message.getCookie());
    }

    private void parseKeyExchangeAlgorithms() {
        message.setKeyExchangeAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Key exchange algorithms length: "
                        + message.getKeyExchangeAlgorithmsLength().getValue());
        message.setKeyExchangeAlgorithms(
                parseByteString(
                        message.getKeyExchangeAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug("Key exchange algorithms: " + message.getKeyExchangeAlgorithms().getValue());
    }

    private void parseServerHostKeyAlgorithms() {
        message.setServerHostKeyAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Server host key algorithms length: "
                        + message.getServerHostKeyAlgorithmsLength().getValue());
        message.setServerHostKeyAlgorithms(
                parseByteString(
                        message.getServerHostKeyAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Server host key algorithms: " + message.getServerHostKeyAlgorithms().getValue());
    }

    private void parseEncryptionAlgorithmsClientToServer() {
        message.setEncryptionAlgorithmsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Encryption algorithms length (client to server): "
                        + message.getEncryptionAlgorithmsClientToServerLength().getValue());
        message.setEncryptionAlgorithmsClientToServer(
                parseByteString(
                        message.getEncryptionAlgorithmsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Encryption algorithms (client to server): "
                        + message.getEncryptionAlgorithmsClientToServer().getValue());
    }

    private void parseEncryptionAlgorithmsServerToClient() {
        message.setEncryptionAlgorithmsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Encryption algorithms length (server to client): "
                        + message.getEncryptionAlgorithmsServerToClientLength().getValue());
        message.setEncryptionAlgorithmsServerToClient(
                parseByteString(
                        message.getEncryptionAlgorithmsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Encryption algorithms (server to client): "
                        + message.getEncryptionAlgorithmsServerToClient().getValue());
    }

    private void parseMacAlgorithmsClientToServer() {
        message.setMacAlgorithmsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "MAC algorithms length (client to server): "
                        + message.getMacAlgorithmsClientToServerLength().getValue());
        message.setMacAlgorithmsClientToServer(
                parseByteString(
                        message.getMacAlgorithmsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "MAC algorithms (client to server): "
                        + message.getMacAlgorithmsClientToServer().getValue());
    }

    private void parseMacAlgorithmsServerToClient() {
        message.setMacAlgorithmsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "MAC algorithms length (server to client): "
                        + message.getMacAlgorithmsServerToClientLength().getValue());
        message.setMacAlgorithmsServerToClient(
                parseByteString(
                        message.getMacAlgorithmsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "MAC algorithms (server to client): "
                        + message.getMacAlgorithmsServerToClient().getValue());
    }

    private void parseCompressionAlgorithmsClientToServer() {
        message.setCompressionAlgorithmsClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Compression algorithms length (client to server): "
                        + message.getCompressionAlgorithmsClientToServerLength().getValue());
        message.setCompressionAlgorithmsClientToServer(
                parseByteString(
                        message.getCompressionAlgorithmsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (client to server): "
                        + message.getCompressionAlgorithmsClientToServer().getValue());
    }

    private void parseCompressionAlgorithmsServerToClient() {
        message.setCompressionAlgorithmsServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Compression algorithms length (server to client): "
                        + message.getCompressionAlgorithmsServerToClientLength().getValue());
        message.setCompressionAlgorithmsServerToClient(
                parseByteString(
                        message.getCompressionAlgorithmsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (server to client): "
                        + message.getCompressionAlgorithmsServerToClient().getValue());
    }

    private void parseLanguagesClientToServer() {
        message.setLanguagesClientToServerLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Languages length (client to server): "
                        + message.getLanguagesClientToServerLength().getValue());
        message.setLanguagesClientToServer(
                parseByteString(
                        message.getLanguagesClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Languages (client to server): " + message.getLanguagesClientToServer().getValue());
    }

    private void parseLanguagesServerToClient() {
        message.setLanguagesServerToClientLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Languages length (server to client): "
                        + message.getLanguagesServerToClientLength().getValue());
        message.setLanguagesServerToClient(
                parseByteString(
                        message.getLanguagesServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Languages (server to client): " + message.getLanguagesServerToClient().getValue());
    }

    private void parseFirstKeyExchangePacketFollows() {
        message.setFirstKeyExchangePacketFollows(parseByteField(1));
        LOGGER.debug(
                "First key exchange packet follows: "
                        + Converter.byteToBoolean(
                                message.getFirstKeyExchangePacketFollows().getValue()));
    }

    private void parseReserved() {
        message.setReserved(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Reserved: " + message.getReserved().getValue());
    }

    @Override
    public void parseMessageSpecificContents() {
        parseCookie();
        parseKeyExchangeAlgorithms();
        parseServerHostKeyAlgorithms();
        parseEncryptionAlgorithmsClientToServer();
        parseEncryptionAlgorithmsServerToClient();
        parseMacAlgorithmsClientToServer();
        parseMacAlgorithmsServerToClient();
        parseCompressionAlgorithmsClientToServer();
        parseCompressionAlgorithmsServerToClient();
        parseLanguagesClientToServer();
        parseLanguagesServerToClient();
        parseFirstKeyExchangePacketFollows();
        parseReserved();
    }
}
