/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AsciiMessageSerializer extends ProtocolMessageSerializer<AsciiMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AsciiMessageSerializer(final AsciiMessage message) {
        super(message);
    }

    private void serializeText() {
        final String text = message.getText().getValue();
        if (text.isEmpty()) {
            LOGGER.debug("Text: [none]");
        } else {
            LOGGER.debug("Text: " + text);
            appendString(text, StandardCharsets.US_ASCII);
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

    @Override
    protected void serializeProtocolMessageContents() {
        serializeText();
        serializeEndOfMessageSequence();
    }
}
