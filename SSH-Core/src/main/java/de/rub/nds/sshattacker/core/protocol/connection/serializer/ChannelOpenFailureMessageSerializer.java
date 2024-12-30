/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenFailureMessageSerializer
        extends ChannelMessageSerializer<ChannelOpenFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeReasonCode(
            ChannelOpenFailureMessage object, SerializerStream output) {
        Integer reasonCode = object.getReasonCode().getValue();
        LOGGER.debug("Reason code: {}", reasonCode);
        output.appendInt(reasonCode);
    }

    private static void serializeReason(ChannelOpenFailureMessage object, SerializerStream output) {
        Integer reasonLength = object.getReasonLength().getValue();
        LOGGER.debug("Reason length: {}", reasonLength);
        output.appendInt(reasonLength);
        String reason = object.getReason().getValue();
        LOGGER.debug("Reason: {}", () -> backslashEscapeString(reason));
        output.appendString(reason, StandardCharsets.UTF_8);
    }

    private static void serializeLanguageTag(
            ChannelOpenFailureMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenFailureMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeReasonCode(object, output);
        serializeReason(object, output);
        serializeLanguageTag(object, output);
    }
}
