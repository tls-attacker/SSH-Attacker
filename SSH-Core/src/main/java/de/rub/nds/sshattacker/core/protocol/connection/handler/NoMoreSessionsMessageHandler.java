/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.NoMoreSessionsMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.NoMoreSessionsMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.NoMoreSessionsMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.NoMoreSessionsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NoMoreSessionsMessageHandler extends SshMessageHandler<NoMoreSessionsMessage> {

    public NoMoreSessionsMessageHandler(SshContext context) {
        super(context);
    }

    public NoMoreSessionsMessageHandler(SshContext context, NoMoreSessionsMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public SshMessageParser<NoMoreSessionsMessage> getParser(byte[] array, int startPosition) {
        return new NoMoreSessionsMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<NoMoreSessionsMessage> getPreparator() {
        return new NoMoreSessionsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<NoMoreSessionsMessage> getSerializer() {
        return new NoMoreSessionsMessageSerializer(message);
    }
}
