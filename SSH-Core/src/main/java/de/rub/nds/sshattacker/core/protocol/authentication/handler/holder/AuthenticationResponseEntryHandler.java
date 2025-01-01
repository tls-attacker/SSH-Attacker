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

    @Override
    public void adjustContext(SshContext context, AuthenticationResponseEntry object) {}

    @Override
    public AuthenticationResponseEntryParser getParser(byte[] array, SshContext context) {
        return new AuthenticationResponseEntryParser(array);
    }

    @Override
    public AuthenticationResponseEntryParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new AuthenticationResponseEntryParser(array, startPosition);
    }

    public static final AuthenticationResponseEntryPreparator PREPARATOR =
            new AuthenticationResponseEntryPreparator();

    public static final AuthenticationResponseEntrySerializer SERIALIZER =
            new AuthenticationResponseEntrySerializer();
}
