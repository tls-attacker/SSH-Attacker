/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestNoMoreSessionsOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestNoMoreSessionsOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestNoMoreSessionsOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestNoMoreSessionsOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestNoMoreSessionsOpenSshMessage> {

    public GlobalRequestNoMoreSessionsOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestNoMoreSessionsOpenSshMessageHandler(
            SshContext context, GlobalRequestNoMoreSessionsOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle GlobalRequestNoMoreSessionsOpenSshMessage
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageParser getParser(byte[] array) {
        return new GlobalRequestNoMoreSessionsOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestNoMoreSessionsOpenSshMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessagePreparator getPreparator() {
        return new GlobalRequestNoMoreSessionsOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageSerializer getSerializer() {
        return new GlobalRequestNoMoreSessionsOpenSshMessageSerializer(message);
    }
}
