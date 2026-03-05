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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AsciiMessageSerializer extends ProtocolMessageSerializer<AsciiMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeText(AsciiMessage object, SerializerStream output) {
        String text = object.getText().getValue();
        if (text.isEmpty()) {
            LOGGER.debug("Text: [none]");
        } else {
            LOGGER.debug("Text: {}", () -> backslashEscapeString(text));
            output.appendString(text, StandardCharsets.US_ASCII);
        }
    }

    private static void serializeEndOfMessageSequence(
            AsciiMessage object, SerializerStream output) {
        LOGGER.debug(
                "End of Line Sequence: {}",
                object.getEndOfMessageSequence()
                        .getValue()
                        .replace("\r", "[CR]")
                        .replace("\n", "[NL]"));
        output.appendString(object.getEndOfMessageSequence().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeProtocolMessageContents(AsciiMessage object, SerializerStream output) {
        serializeText(object, output);
        serializeEndOfMessageSequence(object, output);
    }
}
