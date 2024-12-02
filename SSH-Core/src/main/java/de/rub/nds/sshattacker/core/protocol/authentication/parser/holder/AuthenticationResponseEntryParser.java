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
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationResponseEntryParser extends Parser<AuthenticationResponseEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AuthenticationResponseEntry authenticationResponseEntry =
            new AuthenticationResponseEntry();

    public AuthenticationResponseEntryParser(byte[] array) {
        super(array);
    }

    public AuthenticationResponseEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseResponse() {
        int responseLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        authenticationResponseEntry.setResponseLength(responseLength);
        LOGGER.debug("Response length: {}", responseLength);
        String response = parseByteString(responseLength, StandardCharsets.UTF_8);
        authenticationResponseEntry.setResponse(response);
        LOGGER.debug("Response: {}", () -> backslashEscapeString(response));
    }

    @Override
    public final AuthenticationResponseEntry parse() {
        parseResponse();
        return authenticationResponseEntry;
    }
}
