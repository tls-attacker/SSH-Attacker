/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestUnknownMessageHandler
        extends SshMessageHandler<GlobalRequestUnknownMessage> {

    public GlobalRequestUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestUnknownMessageHandler(
            SshContext context, GlobalRequestUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public GlobalRequestUnknownMessageParser getParser(byte[] array) {
        return new GlobalRequestUnknownMessageParser(array);
    }

    @Override
    public GlobalRequestUnknownMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestUnknownMessageParser(array, startPosition);
    }

    public static final GlobalRequestUnknownMessagePreparator PREPARATOR =
            new GlobalRequestUnknownMessagePreparator();

    public static final GlobalRequestUnknownMessageSerializer SERIALIZER =
            new GlobalRequestUnknownMessageSerializer();
}
