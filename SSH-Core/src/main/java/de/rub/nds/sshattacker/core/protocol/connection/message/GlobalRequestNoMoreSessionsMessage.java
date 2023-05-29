/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestNoMoreSessionsMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestNoMoreSessionsMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestNoMoreSessionsMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestNoMoreSessionsMessageSerializer;
import java.io.InputStream;

public class GlobalRequestNoMoreSessionsMessage
        extends GlobalRequestMessage<GlobalRequestNoMoreSessionsMessage> {

    @Override
    public GlobalRequestNoMoreSessionsMessageHandler getHandler(SshContext context) {
        return new GlobalRequestNoMoreSessionsMessageHandler(context);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessageParser getParser(
            SshContext context, InputStream stream) {
        return new GlobalRequestNoMoreSessionsMessageParser(stream);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessagePreparator getPreparator(SshContext context) {
        return new GlobalRequestNoMoreSessionsMessagePreparator(context.getChooser(), this);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessageSerializer getSerializer(SshContext context) {
        return new GlobalRequestNoMoreSessionsMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_NO_MORE_SESSIONS";
    }
}
