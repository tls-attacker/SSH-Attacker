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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

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
        LOGGER.debug("Description length: {}", message.getDescriptionLength().getValue());
        appendInt(
                message.getDescriptionLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: {}", message.getDescription().getValue());
        appendString(message.getDescription().getValue(), StandardCharsets.UTF_8);
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
        serializeReasonCode();
        serializeDescription();
        serializeLanguageTag();
    }
}
