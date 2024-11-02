/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

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
        LOGGER.debug("Reason code: {}", message.getReasonCode());
    }

    private void parseReason() {
        int reasonLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setReasonLength(reasonLength);
        LOGGER.debug("Reason length: {}", reasonLength);
        String reason = parseByteString(reasonLength, StandardCharsets.UTF_8);
        message.setReason(reason);
        LOGGER.debug("Reason: {}", () -> backslashEscapeString(reason));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseReasonCode();
        parseReason();
        parseLanguageTag();
    }
}
