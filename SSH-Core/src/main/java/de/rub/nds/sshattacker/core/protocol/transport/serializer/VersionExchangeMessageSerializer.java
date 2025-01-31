/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSerializer
        extends ProtocolMessageSerializer<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeVersion(VersionExchangeMessage object, SerializerStream output) {
        if (object.getVersion().getValue().isEmpty()) {
            LOGGER.debug("Version: [none]");
        } else {
            String version = object.getVersion().getValue();
            LOGGER.debug("Version: {}", version);
            output.appendString(version, StandardCharsets.US_ASCII);
        }
    }

    private static void serializeComment(VersionExchangeMessage object, SerializerStream output) {
        String comment = object.getComment().getValue();
        if (comment.isEmpty()) {
            LOGGER.debug("Comment: [none]");
        } else {
            output.appendString(
                    String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR),
                    StandardCharsets.US_ASCII);
            LOGGER.debug("Comment: {}", comment);
            output.appendString(comment, StandardCharsets.US_ASCII);
        }
    }

    private static void serializeEndOfMessageSequence(
            VersionExchangeMessage object, SerializerStream output) {
        LOGGER.debug(
                "End of Line Sequence: {}",
                object.getEndOfMessageSequence()
                        .getValue()
                        .replace("\r", "[CR]")
                        .replace("\n", "[NL]"));
        output.appendString(object.getEndOfMessageSequence().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeProtocolMessageContents(
            VersionExchangeMessage object, SerializerStream output) {
        serializeVersion(object, output);
        serializeComment(object, output);
        serializeEndOfMessageSequence(object, output);
    }
}
