/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageSerializer extends SshMessageSerializer<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageSerializer(DisconnectMessage message) {
        super(message);
    }

    private void serializeReasonCode() {
        LOGGER.debug(
                "Reason: {} (Code: {})",
                DisconnectReason.fromId(message.getReasonCode().getValue()),
                message.getReasonCode().getValue());
        appendInt(message.getReasonCode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeDescription() {
        Integer descriptionLength = message.getDescriptionLength().getValue();
        LOGGER.debug("Description length: {}", descriptionLength);
        appendInt(descriptionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: {}", message.getDescription().getValue());
        appendString(message.getDescription().getValue(), StandardCharsets.UTF_8);
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
        serializeReasonCode();
        serializeDescription();
        serializeLanguageTag();
    }
}
