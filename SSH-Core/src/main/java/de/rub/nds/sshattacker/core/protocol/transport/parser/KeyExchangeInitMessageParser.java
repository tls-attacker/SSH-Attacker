/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeInitConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class KeyExchangeInitMessageParser extends MessageParser<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseCookie(KeyExchangeInitMessage msg) {
        msg.setCookie(parseByteArrayField(KeyExchangeInitConstants.COOKIE_LENGTH));
        LOGGER.debug("Cookie: " + msg.getCookie());
    }

    private void parseKeyExchangeAlgorithms(KeyExchangeInitMessage msg) {
        msg.setKeyExchangeAlgorithmsLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Key exchange algorithms length: " + msg.getKeyExchangeAlgorithmsLength().getValue());
        msg.setKeyExchangeAlgorithms(parseByteString(msg.getKeyExchangeAlgorithmsLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("Key exchange algorithms: " + msg.getKeyExchangeAlgorithms().getValue());
    }

    private void parseServerHostKeyAlgorithms(KeyExchangeInitMessage msg) {
        msg.setServerHostKeyAlgorithmsLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Server host key algorithms length: " + msg.getServerHostKeyAlgorithmsLength().getValue());
        msg.setServerHostKeyAlgorithms(parseByteString(msg.getServerHostKeyAlgorithmsLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("Server host key algorithms: " + msg.getServerHostKeyAlgorithms().getValue());
    }

    private void parseEncryptionAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsClientToServerLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Encryption algorithms length (client to server): "
                + msg.getEncryptionAlgorithmsClientToServerLength().getValue());
        msg.setEncryptionAlgorithmsClientToServer(parseByteString(msg.getEncryptionAlgorithmsClientToServerLength()
                .getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Encryption algorithms (client to server): "
                + msg.getEncryptionAlgorithmsClientToServer().getValue());
    }

    private void parseEncryptionAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsServerToClientLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Encryption algorithms length (server to client): "
                + msg.getEncryptionAlgorithmsServerToClientLength().getValue());
        msg.setEncryptionAlgorithmsServerToClient(parseByteString(msg.getEncryptionAlgorithmsServerToClientLength()
                .getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Encryption algorithms (server to client): "
                + msg.getEncryptionAlgorithmsServerToClient().getValue());
    }

    private void parseMacAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsClientToServerLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("MAC algorithms length (client to server): "
                + msg.getMacAlgorithmsClientToServerLength().getValue());
        msg.setMacAlgorithmsClientToServer(parseByteString(msg.getMacAlgorithmsClientToServerLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("MAC algorithms (client to server): " + msg.getMacAlgorithmsClientToServer().getValue());
    }

    private void parseMacAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsServerToClientLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("MAC algorithms length (server to client): "
                + msg.getMacAlgorithmsServerToClientLength().getValue());
        msg.setMacAlgorithmsServerToClient(parseByteString(msg.getMacAlgorithmsServerToClientLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("MAC algorithms (server to client): " + msg.getMacAlgorithmsServerToClient().getValue());
    }

    private void parseCompressionAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsClientToServerLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Compression algorithms length (client to server): "
                + msg.getCompressionAlgorithmsClientToServerLength().getValue());
        msg.setCompressionAlgorithmsClientToServer(parseByteString(msg.getCompressionAlgorithmsClientToServerLength()
                .getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Compression algorithms (client to server): "
                + msg.getCompressionAlgorithmsClientToServer().getValue());
    }

    private void parseCompressionAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsServerToClientLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Compression algorithms length (server to client): "
                + msg.getCompressionAlgorithmsServerToClientLength().getValue());
        msg.setCompressionAlgorithmsServerToClient(parseByteString(msg.getCompressionAlgorithmsServerToClientLength()
                .getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Compression algorithms (server to client): "
                + msg.getCompressionAlgorithmsServerToClient().getValue());
    }

    private void parseLanguagesClientToServer(KeyExchangeInitMessage msg) {
        msg.setLanguagesClientToServerLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Languages length (client to server): " + msg.getLanguagesClientToServerLength().getValue());
        msg.setLanguagesClientToServer(parseByteString(msg.getLanguagesClientToServerLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("Languages (client to server): " + msg.getLanguagesClientToServer().getValue());
    }

    private void parseLanguagesServerToClient(KeyExchangeInitMessage msg) {
        msg.setLanguagesServerToClientLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Languages length (server to client): " + msg.getLanguagesServerToClientLength().getValue());
        msg.setLanguagesServerToClient(parseByteString(msg.getLanguagesServerToClientLength().getValue(),
                StandardCharsets.US_ASCII));
        LOGGER.debug("Languages (server to client): " + msg.getLanguagesServerToClient().getValue());
    }

    private void parseFirstKeyExchangePacketFollows(KeyExchangeInitMessage msg) {
        msg.setFirstKeyExchangePacketFollows(parseByteField(1));
        LOGGER.debug("First key exchange packet follows: "
                + Converter.byteToBoolean(msg.getFirstKeyExchangePacketFollows().getValue()));
    }

    private void parseReserved(KeyExchangeInitMessage msg) {
        msg.setReserved(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Reserved: " + msg.getReserved().getValue());
    }

    @Override
    public void parseMessageSpecificPayload(KeyExchangeInitMessage msg) {
        parseCookie(msg);
        parseKeyExchangeAlgorithms(msg);
        parseServerHostKeyAlgorithms(msg);
        parseEncryptionAlgorithmsClientToServer(msg);
        parseEncryptionAlgorithmsServerToClient(msg);
        parseMacAlgorithmsClientToServer(msg);
        parseMacAlgorithmsServerToClient(msg);
        parseCompressionAlgorithmsClientToServer(msg);
        parseCompressionAlgorithmsServerToClient(msg);
        parseLanguagesClientToServer(msg);
        parseLanguagesServerToClient(msg);
        parseFirstKeyExchangePacketFollows(msg);
        parseReserved(msg);
    }

    @Override
    public KeyExchangeInitMessage createMessage() {
        return new KeyExchangeInitMessage();
    }
}
