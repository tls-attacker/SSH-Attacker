/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends SshMessageParser<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageParser(byte[] array) {
        super(array);
    }

    public DisconnectMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DisconnectMessage createMessage() {
        return new DisconnectMessage();
    }

    private void parseReasonCode() {
        message.setReasonCode(parseIntField());
        if (DisconnectReason.fromId(message.getReasonCode().getValue()) != null) {
            LOGGER.debug(
                    "Reason: {} (Code: {})",
                    DisconnectReason.fromId(message.getReasonCode().getValue()).toString(),
                    message.getReasonCode().getValue());
        } else {
            LOGGER.debug("Reason: [unknown] (Code: {})", message.getReasonCode().getValue());
        }
    }

    private void parseDescription() {
        int descriptionLength = parseIntField();
        message.setDescriptionLength(descriptionLength);
        LOGGER.debug("Description length: {}", descriptionLength);
        String description = parseByteString(descriptionLength, StandardCharsets.UTF_8);
        message.setDescription(description);
        LOGGER.debug("Description: {}", () -> backslashEscapeString(description));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField();
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseReasonCode();
        parseDescription();
        parseLanguageTag();
    }
}
