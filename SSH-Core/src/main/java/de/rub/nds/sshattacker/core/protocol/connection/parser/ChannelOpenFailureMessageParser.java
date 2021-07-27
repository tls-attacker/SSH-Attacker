/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessageParser extends ChannelMessageParser<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelOpenFailureMessage createMessage() {
        return new ChannelOpenFailureMessage();
    }

    private void parseReasonCode(ChannelOpenFailureMessage msg) {
        msg.setReasonCode(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Reason code: " + msg.getReasonCode());
    }

    private void parseReason(ChannelOpenFailureMessage msg) {
        msg.setReasonLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Reason length: " + msg.getReasonLength());
        msg.setReason(parseByteString(msg.getReasonLength().getValue(), StandardCharsets.UTF_8), false);
        LOGGER.debug("Reason: " + msg.getReason().getValue());
    }

    private void parseLanguageTag(ChannelOpenFailureMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        msg.setLanguageTag(parseByteString(msg.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII), false);
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenFailureMessage msg) {
        super.parseMessageSpecificPayload(msg);
        parseReasonCode(msg);
        parseReason(msg);
        parseLanguageTag(msg);
    }
}
