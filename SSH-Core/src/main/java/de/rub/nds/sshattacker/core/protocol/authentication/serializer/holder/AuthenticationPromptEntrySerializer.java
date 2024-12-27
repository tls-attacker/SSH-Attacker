/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationPromptEntrySerializer extends Serializer<AuthenticationPromptEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeEcho(AuthenticationPromptEntry object, SerializerStream output) {
        byte echo = object.getEcho().getValue();
        LOGGER.debug("Echo: {}", echo);
        output.appendByte(echo);
    }

    private static void serializePrompt(AuthenticationPromptEntry object, SerializerStream output) {
        Integer promptLength = object.getPromptLength().getValue();
        LOGGER.debug("Prompt length: {}", promptLength);
        output.appendInt(promptLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String prompt = object.getPrompt().getValue();
        LOGGER.debug("Prompt: {}", () -> backslashEscapeString(prompt));
        output.appendString(prompt, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes(AuthenticationPromptEntry object, SerializerStream output) {
        serializePrompt(object, output);
        serializeEcho(object, output);
    }
}
