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
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class DebugMessageParser extends MessageParser<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseAlwaysDisplay(DebugMessage msg) {
        msg.setAlwaysDisplay(parseByteField(1));
        LOGGER.debug("Always display: " + Converter.byteToBoolean(msg.getAlwaysDisplay().getValue()));
    }

    private void parseMessage(DebugMessage msg) {
        msg.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Message length: " + msg.getMessageLength().getValue());
        msg.setMessage(parseByteString(msg.getMessageLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Message: " + msg.getMessage().getValue());
    }

    private void parseLanguageTag(DebugMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        msg.setLanguageTag(parseByteString(msg.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(DebugMessage msg) {
        parseAlwaysDisplay(msg);
        parseMessage(msg);
        parseLanguageTag(msg);
    }

    @Override
    public DebugMessage createMessage() {
        return new DebugMessage();
    }
}
