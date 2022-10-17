/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenFailureMessageParser
        extends ChannelMessageParser<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenFailureMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelOpenFailureMessage createMessage() {
        return new ChannelOpenFailureMessage();
    }

    private void parseReasonCode() {
        message.setReasonCode(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Reason code: " + message.getReasonCode());
    }

    private void parseReason() {
        message.setReasonLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Reason length: " + message.getReasonLength());
        message.setReason(
                parseByteString(message.getReasonLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Reason: " + message.getReason().getValue());
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseReasonCode();
        parseReason();
        parseLanguageTag();
    }
}
