/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestNoMoreSessionsMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestNoMoreSessionsMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestNoMoreSessionsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestNoMoreSessionsMessageHandler
        extends SshMessageHandler<GlobalRequestNoMoreSessionsMessage> {

    @Override
    public void adjustContext(SshContext context, GlobalRequestNoMoreSessionsMessage object) {}

    @Override
    public GlobalRequestNoMoreSessionsMessageParser getParser(byte[] array, SshContext context) {
        return new GlobalRequestNoMoreSessionsMessageParser(array);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestNoMoreSessionsMessageParser(array, startPosition);
    }

    public static final GlobalRequestNoMoreSessionsMessagePreparator PREPARATOR =
            new GlobalRequestNoMoreSessionsMessagePreparator();

    public static final GlobalRequestNoMoreSessionsMessageSerializer SERIALIZER =
            new GlobalRequestNoMoreSessionsMessageSerializer();
}
