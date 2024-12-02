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
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationResponseEntrySerializer extends Serializer<AuthenticationResponseEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AuthenticationResponseEntry authenticationResponseEntry;

    public AuthenticationResponseEntrySerializer(
            AuthenticationResponseEntry authenticationResponseEntry) {
        super();
        this.authenticationResponseEntry = authenticationResponseEntry;
    }

    private void serializeResponse() {
        Integer responseLength = authenticationResponseEntry.getResponseLength().getValue();
        LOGGER.debug("Response length: {}", responseLength);
        appendInt(responseLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String response = authenticationResponseEntry.getResponse().getValue();
        LOGGER.debug("Response: {}", () -> backslashEscapeString(response));
        appendString(response, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes() {
        serializeResponse();
    }
}
