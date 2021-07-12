/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeInitConstants;
import de.rub.nds.sshattacker.core.protocol.message.KeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageParser extends MessageParser<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseCookie(KeyExchangeInitMessage msg) {
        msg.setCookie(parseByteArrayField(KeyExchangeInitConstants.COOKIE_LENGTH));
        LOGGER.debug("Cookie: " + msg.getCookie());
    }

    private void parseKeyExchangeAlgorithmsLength(KeyExchangeInitMessage msg) {
        msg.setKeyExchangeAlgorithmsLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("KeyExchangeAlgorithmsLength: " + msg.getKeyExchangeAlgorithmsLength().getValue());
    }

    private void parseKeyExchangeAlgorithms(KeyExchangeInitMessage msg) {
        msg.setKeyExchangeAlgorithms(parseByteString(msg.getKeyExchangeAlgorithmsLength().getValue()));
        LOGGER.debug("KeyExchangeAlgorithms: " + msg.getKeyExchangeAlgorithms().getValue());
    }

    private void parseServerHostKeyAlgorithmsLength(KeyExchangeInitMessage msg) {
        msg.setServerHostKeyAlgorithmsLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("ServerHostKeyAlgorithmsLength: " + msg.getServerHostKeyAlgorithmsLength().getValue());
    }

    private void parseServerHostKeyAlgorithms(KeyExchangeInitMessage msg) {
        msg.setServerHostKeyAlgorithms(parseByteString(msg.getServerHostKeyAlgorithmsLength().getValue()));
        LOGGER.debug("ServerHostKeyAlgorithms: " + msg.getServerHostKeyAlgorithms().getValue());
    }

    private void parseEncryptionAlgorithmsClientToServerLength(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsClientToServerLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EncryptionAlgorithmsClientToServerLength: "
                + msg.getEncryptionAlgorithmsClientToServerLength().getValue());
    }

    private void parseEncryptionAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsClientToServer(parseByteString(msg.getEncryptionAlgorithmsClientToServerLength()
                .getValue()));
        LOGGER.debug("EncryptionAlgorithmsClientToServer: " + msg.getEncryptionAlgorithmsClientToServer().getValue());
    }

    private void parseEncryptionAlgorithmsServerToClientLength(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsServerToClientLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("EncryptionAlgorithmsServerToClientLength: "
                + msg.getEncryptionAlgorithmsServerToClientLength().getValue());
    }

    private void parseEncryptionAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setEncryptionAlgorithmsServerToClient(parseByteString(msg.getEncryptionAlgorithmsServerToClientLength()
                .getValue()));
        LOGGER.debug("EncryptionAlgorithmsServerToClient: " + msg.getEncryptionAlgorithmsServerToClient().getValue());
    }

    private void parseMacAlgorithmsClientToServerLength(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsClientToServerLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("MacAlgorithmsClientToServerLength: " + msg.getMacAlgorithmsClientToServerLength().getValue());
    }

    private void parseMacAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsClientToServer(parseByteString(msg.getMacAlgorithmsClientToServerLength().getValue()));
        LOGGER.debug("MacAlgorithmsClientToServer: " + msg.getMacAlgorithmsClientToServer().getValue());
    }

    private void parseMacAlgorithmsServerToClientLength(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsServerToClientLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("MacAlgorithmsServerToClientLength: " + msg.getMacAlgorithmsServerToClientLength().getValue());
    }

    private void parseMacAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setMacAlgorithmsServerToClient(parseByteString(msg.getMacAlgorithmsServerToClientLength().getValue()));
        LOGGER.debug("MacAlgorithmsServerToClient: " + msg.getMacAlgorithmsServerToClient().getValue());
    }

    private void parseCompressionAlgorithmsClientToServerLength(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsClientToServerLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("CompressionAlgorithmsClientToServerLength: "
                + msg.getCompressionAlgorithmsClientToServerLength().getValue());
    }

    private void parseCompressionAlgorithmsClientToServer(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsClientToServer(parseByteString(msg.getCompressionAlgorithmsClientToServerLength()
                .getValue()));
        LOGGER.debug("CompressionAlgorithmsClientToServer: " + msg.getCompressionAlgorithmsClientToServer().getValue());
    }

    private void parseCompressionAlgorithmsServerToClientLength(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsServerToClientLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("CompressionAlgorithmsServerToClientLength: "
                + msg.getCompressionAlgorithmsServerToClientLength().getValue());
    }

    private void parseCompressionAlgorithmsServerToClient(KeyExchangeInitMessage msg) {
        msg.setCompressionAlgorithmsServerToClient(parseByteString(msg.getCompressionAlgorithmsServerToClientLength()
                .getValue()));
        LOGGER.debug("CompressionAlgorithmsServerToClient" + msg.getCompressionAlgorithmsServerToClient().getValue());
    }

    private void parseLanguagesClientToServerLength(KeyExchangeInitMessage msg) {
        msg.setLanguagesClientToServerLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("LanguagesClientToServerLength: " + msg.getLanguagesClientToServerLength().getValue());
    }

    private void parseLanguagesClientToServer(KeyExchangeInitMessage msg) {
        msg.setLanguagesClientToServer(parseByteString(msg.getLanguagesClientToServerLength().getValue()));
        LOGGER.debug("LanguagesClientToServer: " + msg.getLanguagesClientToServer().getValue());
    }

    private void parseLanguagesServerToClientLength(KeyExchangeInitMessage msg) {
        msg.setLanguagesServerToClientLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("LanguagesServerToClientLength: " + msg.getLanguagesServerToClientLength().getValue());
    }

    private void parseLanguagesServerToClient(KeyExchangeInitMessage msg) {
        msg.setLanguagesServerToClient(parseByteString(msg.getLanguagesServerToClientLength().getValue()));
        LOGGER.debug("LanguagesServerToClient: " + msg.getLanguagesServerToClient().getValue());
    }

    private void parseFirstKeyExchangePacketFollows(KeyExchangeInitMessage msg) {
        msg.setFirstKeyExchangePacketFollows(parseByteField(1) != 0);
        LOGGER.debug("FirstKeyExchangePacketFollows: " + msg.getFirstKeyExchangePacketFollows().getValue());
    }

    private void parseReserved(KeyExchangeInitMessage msg) {
        msg.setReserved(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Reserved: " + msg.getReserved().getValue());
    }

    @Override
    public void parseMessageSpecificPayload(KeyExchangeInitMessage msg) {
        parseCookie(msg);
        parseKeyExchangeAlgorithmsLength(msg);
        parseKeyExchangeAlgorithms(msg);
        parseServerHostKeyAlgorithmsLength(msg);
        parseServerHostKeyAlgorithms(msg);
        parseEncryptionAlgorithmsClientToServerLength(msg);
        parseEncryptionAlgorithmsClientToServer(msg);
        parseEncryptionAlgorithmsServerToClientLength(msg);
        parseEncryptionAlgorithmsServerToClient(msg);
        parseMacAlgorithmsClientToServerLength(msg);
        parseMacAlgorithmsClientToServer(msg);
        parseMacAlgorithmsServerToClientLength(msg);
        parseMacAlgorithmsServerToClient(msg);
        parseCompressionAlgorithmsClientToServerLength(msg);
        parseCompressionAlgorithmsClientToServer(msg);
        parseCompressionAlgorithmsServerToClientLength(msg);
        parseCompressionAlgorithmsServerToClient(msg);
        parseLanguagesClientToServerLength(msg);
        parseLanguagesClientToServer(msg);
        parseLanguagesServerToClientLength(msg);
        parseLanguagesServerToClient(msg);
        parseFirstKeyExchangePacketFollows(msg);
        parseReserved(msg);
    }

    @Override
    public KeyExchangeInitMessage createMessage() {
        return new KeyExchangeInitMessage();
    }
}
