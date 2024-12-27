/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestSuccessMessageHandler
        extends SshMessageHandler<GlobalRequestSuccessMessage> {

    public GlobalRequestSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestSuccessMessageHandler(
            SshContext context, GlobalRequestSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle RequestSuccessMessage
    }

    @Override
    public GlobalRequestSuccessMessageParser getParser(byte[] array) {
        return new GlobalRequestSuccessMessageParser(array);
    }

    @Override
    public GlobalRequestSuccessMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestSuccessMessageParser(array, startPosition);
    }

    public static final GlobalRequestSuccessMessagePreparator PREPARATOR =
            new GlobalRequestSuccessMessagePreparator();

    @Override
    public GlobalRequestSuccessMessageSerializer getSerializer() {
        return new GlobalRequestSuccessMessageSerializer(message);
    }
}
