/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelOpenFailureMessageSerializer
        extends ChannelMessageSerializer<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageSerializer(ChannelOpenFailureMessage message) {
        super(message);
    }

    private void serializeReasonCode() {
        LOGGER.debug("Reason code: {}", message.getReasonCode().getValue());
        appendInt(message.getReasonCode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeReason() {
        LOGGER.debug("Reason length: {}", message.getReasonLength().getValue());
        appendInt(message.getReasonLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Reason: {}", backslashEscapeString(message.getReason().getValue()));
        appendString(message.getReason().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Language tag: {}", backslashEscapeString(message.getLanguageTag().getValue()));
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeReasonCode();
        serializeReason();
        serializeLanguageTag();
    }
}
