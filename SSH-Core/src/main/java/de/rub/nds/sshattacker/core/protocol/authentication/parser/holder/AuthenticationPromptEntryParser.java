/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationPromptEntryParser extends Parser<AuthenticationPromptEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AuthenticationPromptEntry authenticationPromptEntry =
            new AuthenticationPromptEntry();

    public AuthenticationPromptEntryParser(byte[] array) {
        super(array);
    }

    public AuthenticationPromptEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseEcho() {
        byte echo = parseByteField(1);
        authenticationPromptEntry.setEcho(echo);
        LOGGER.debug("Echo: {}", echo);
    }

    private void parsePrompt() {
        int promptLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        authenticationPromptEntry.setPromptLength(promptLength);
        LOGGER.debug("Prompt length: {}", promptLength);
        String prompt = parseByteString(promptLength, StandardCharsets.UTF_8);
        authenticationPromptEntry.setPrompt(prompt);
        LOGGER.debug("Prompt: {}", () -> backslashEscapeString(prompt));
    }

    @Override
    public final AuthenticationPromptEntry parse() {
        parsePrompt();
        parseEcho();
        return authenticationPromptEntry;
    }
}
