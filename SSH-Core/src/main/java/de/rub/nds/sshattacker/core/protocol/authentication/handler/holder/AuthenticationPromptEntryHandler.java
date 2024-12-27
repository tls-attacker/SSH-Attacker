/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler.holder;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.holder.AuthenticationPromptEntryParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.holder.AuthenticationPromptEntryPreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.holder.AuthenticationPromptEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class AuthenticationPromptEntryHandler implements Handler<AuthenticationPromptEntry> {

    private final SshContext context;

    private final AuthenticationPromptEntry authenticationPromptEntry;

    public AuthenticationPromptEntryHandler(SshContext context) {
        this(context, null);
    }

    public AuthenticationPromptEntryHandler(
            SshContext context, AuthenticationPromptEntry authenticationPromptEntry) {
        super();
        this.context = context;
        this.authenticationPromptEntry = authenticationPromptEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public AuthenticationPromptEntryParser getParser(byte[] array) {
        return new AuthenticationPromptEntryParser(array);
    }

    @Override
    public AuthenticationPromptEntryParser getParser(byte[] array, int startPosition) {
        return new AuthenticationPromptEntryParser(array, startPosition);
    }

    public static final AuthenticationPromptEntryPreparator PREPARATOR =
            new AuthenticationPromptEntryPreparator();

    @Override
    public AuthenticationPromptEntrySerializer getSerializer() {
        return new AuthenticationPromptEntrySerializer(authenticationPromptEntry);
    }
}
