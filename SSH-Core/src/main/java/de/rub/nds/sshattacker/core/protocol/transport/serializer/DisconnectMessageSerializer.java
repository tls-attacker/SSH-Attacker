/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageSerializer extends SshMessageSerializer<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeReasonCode(DisconnectMessage object, SerializerStream output) {
        LOGGER.debug(
                "Reason: {} (Code: {})",
                DisconnectReason.fromId(object.getReasonCode().getValue()),
                object.getReasonCode().getValue());
        output.appendInt(object.getReasonCode().getValue());
    }

    private static void serializeDescription(DisconnectMessage object, SerializerStream output) {
        Integer descriptionLength = object.getDescriptionLength().getValue();
        LOGGER.debug("Description length: {}", descriptionLength);
        output.appendInt(descriptionLength);
        LOGGER.debug("Description: {}", object.getDescription().getValue());
        output.appendString(object.getDescription().getValue(), StandardCharsets.UTF_8);
    }

    private static void serializeLanguageTag(DisconnectMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            DisconnectMessage object, SerializerStream output) {
        serializeReasonCode(object, output);
        serializeDescription(object, output);
        serializeLanguageTag(object, output);
    }
}
