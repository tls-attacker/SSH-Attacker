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

    @Override
    public void adjustContext(SshContext context, GlobalRequestSuccessMessage object) {
        // TODO: Handle RequestSuccessMessage
    }

    @Override
    public GlobalRequestSuccessMessageParser getParser(byte[] array, SshContext context) {
        return new GlobalRequestSuccessMessageParser(array);
    }

    @Override
    public GlobalRequestSuccessMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestSuccessMessageParser(array, startPosition);
    }

    public static final GlobalRequestSuccessMessagePreparator PREPARATOR =
            new GlobalRequestSuccessMessagePreparator();

    public static final GlobalRequestSuccessMessageSerializer SERIALIZER =
            new GlobalRequestSuccessMessageSerializer();
}
