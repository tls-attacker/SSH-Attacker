/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler.holder;

import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.holder.AuthenticationResponseEntryParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.holder.AuthenticationResponseEntryPreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.holder.AuthenticationResponseEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class AuthenticationResponseEntryHandler implements Handler<AuthenticationResponseEntry> {

    private final SshContext context;

    private final AuthenticationResponseEntry authenticationResponseEntry;

    public AuthenticationResponseEntryHandler(SshContext context) {
        this(context, null);
    }

    public AuthenticationResponseEntryHandler(
            SshContext context, AuthenticationResponseEntry authenticationResponseEntry) {
        super();
        this.context = context;
        this.authenticationResponseEntry = authenticationResponseEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public AuthenticationResponseEntryParser getParser(byte[] array) {
        return new AuthenticationResponseEntryParser(array);
    }

    @Override
    public AuthenticationResponseEntryParser getParser(byte[] array, int startPosition) {
        return new AuthenticationResponseEntryParser(array, startPosition);
    }

    @Override
    public AuthenticationResponseEntryPreparator getPreparator() {
        return new AuthenticationResponseEntryPreparator(
                context.getChooser(), authenticationResponseEntry);
    }

    @Override
    public AuthenticationResponseEntrySerializer getSerializer() {
        return new AuthenticationResponseEntrySerializer(authenticationResponseEntry);
    }
}
