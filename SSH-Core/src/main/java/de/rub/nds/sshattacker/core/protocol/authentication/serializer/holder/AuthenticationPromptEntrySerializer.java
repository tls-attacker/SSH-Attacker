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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationPromptEntrySerializer extends Serializer<AuthenticationPromptEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AuthenticationPromptEntry authenticationPromptEntry;

    public AuthenticationPromptEntrySerializer(
            AuthenticationPromptEntry authenticationPromptEntry) {
        super();
        this.authenticationPromptEntry = authenticationPromptEntry;
    }

    private void serializeEcho() {
        byte echo = authenticationPromptEntry.getEcho().getValue();
        LOGGER.debug("Echo: {}", echo);
        appendInt(echo, DataFormatConstants.UINT32_SIZE);
    }

    private void serializePrompt() {
        Integer promptLength = authenticationPromptEntry.getPromptLength().getValue();
        LOGGER.debug("Prompt length: {}", promptLength);
        appendInt(promptLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String prompt = authenticationPromptEntry.getPrompt().getValue();
        LOGGER.debug("Prompt: {}", () -> backslashEscapeString(prompt));
        appendString(prompt, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes() {
        serializePrompt();
        serializeEcho();
    }
}
