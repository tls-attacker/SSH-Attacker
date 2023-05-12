/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class AsciiMessageSerializer extends ProtocolMessageSerializer<AsciiMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AsciiMessageSerializer(AsciiMessage message) {
        super(message);
    }

    private void serializeText() {
        String text = message.getText().getValue();
        if (text.isEmpty()) {
            LOGGER.debug("Text: [none]");
        } else {
            LOGGER.debug("Text: {}", backslashEscapeString(text));
            appendString(text, StandardCharsets.US_ASCII);
        }
    }

    private void serializeEndOfMessageSequence() {
        LOGGER.debug(
                "End of Line Sequence: {}",
                message.getEndOfMessageSequence()
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
