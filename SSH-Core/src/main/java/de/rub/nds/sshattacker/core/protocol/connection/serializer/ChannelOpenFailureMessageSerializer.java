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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenFailureMessageSerializer
        extends ChannelMessageSerializer<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenFailureMessageSerializer(ChannelOpenFailureMessage message) {
        super(message);
    }

    private void serializeReasonCode() {
        Integer reasonCode = message.getReasonCode().getValue();
        LOGGER.debug("Reason code: {}", reasonCode);
        appendInt(reasonCode, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeReason() {
        Integer reasonLength = message.getReasonLength().getValue();
        LOGGER.debug("Reason length: {}", reasonLength);
        appendInt(reasonLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String reason = message.getReason().getValue();
        LOGGER.debug("Reason: {}", () -> backslashEscapeString(reason));
        appendString(reason, StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        Integer languageTagLength = message.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = message.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeReasonCode();
        serializeReason();
        serializeLanguageTag();
    }
}
