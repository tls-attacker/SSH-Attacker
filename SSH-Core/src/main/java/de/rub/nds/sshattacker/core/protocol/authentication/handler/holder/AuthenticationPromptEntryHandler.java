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

    @Override
    public void adjustContext(SshContext context, AuthenticationPromptEntry object) {}

    @Override
    public AuthenticationPromptEntryParser getParser(byte[] array, SshContext context) {
        return new AuthenticationPromptEntryParser(array);
    }

    @Override
    public AuthenticationPromptEntryParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new AuthenticationPromptEntryParser(array, startPosition);
    }

    public static final AuthenticationPromptEntryPreparator PREPARATOR =
            new AuthenticationPromptEntryPreparator();

    public static final AuthenticationPromptEntrySerializer SERIALIZER =
            new AuthenticationPromptEntrySerializer();
}
