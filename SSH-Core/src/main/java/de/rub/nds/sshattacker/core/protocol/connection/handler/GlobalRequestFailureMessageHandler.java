/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestFailureMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestFailureMessageHandler
        extends SshMessageHandler<GlobalRequestFailureMessage> {

    public GlobalRequestFailureMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestFailureMessageHandler(
            SshContext context, GlobalRequestFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle RequestFailureMessage
    }

    @Override
    public GlobalRequestFailureMessageParser getParser(byte[] array) {
        return new GlobalRequestFailureMessageParser(array);
    }

    @Override
    public GlobalRequestFailureMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestFailureMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestFailureMessagePreparator getPreparator() {
        return new GlobalRequestFailureMessagePreparator(context.getChooser(), message);
    }

    @Override
    public GlobalRequestFailureMessageSerializer getSerializer() {
        return new GlobalRequestFailureMessageSerializer(message);
    }
}
