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
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSerializer
        extends ProtocolMessageSerializer<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionExchangeMessageSerializer(VersionExchangeMessage message) {
        super(message);
    }

    private void serializeVersion() {
        if (message.getVersion().getValue().isEmpty()) {
            LOGGER.debug("Version: [none]");
        } else {
            LOGGER.debug("Version: " + message.getVersion().getValue());
            appendString(message.getVersion().getValue(), StandardCharsets.US_ASCII);
        }
    }

    private void serializeComment() {
        if (message.getComment().getValue().isEmpty()) {
            LOGGER.debug("Comment: [none]");
        } else {
            LOGGER.debug("Comment: " + message.getComment().getValue());
            appendString(
                    String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR),
                    StandardCharsets.US_ASCII);
            appendString(message.getComment().getValue(), StandardCharsets.US_ASCII);
        }
    }

    private void serializeEndOfMessageSequence() {
        LOGGER.debug(
                "End of Line Sequence: "
                        + message.getEndOfMessageSequence()
                                .getValue()
                                .replace("\r", "[CR]")
                                .replace("\n", "[NL]"));
        appendString(message.getEndOfMessageSequence().getValue(), StandardCharsets.US_ASCII);
    }

    // @Override
    protected void serializeProtocolMessageContents() {
        serializeVersion();
        serializeComment();
        serializeEndOfMessageSequence();
    }

}
