/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestFailureMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestFailureMessageHandler
        extends SshMessageHandler<GlobalRequestFailureMessage> {

    @Override
    public void adjustContext(SshContext context, GlobalRequestFailureMessage object) {
        // TODO: Handle RequestFailureMessage
    }

    @Override
    public GlobalRequestFailureMessageParser getParser(byte[] array, SshContext context) {
        return new GlobalRequestFailureMessageParser(array);
    }

    @Override
    public GlobalRequestFailureMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestFailureMessageParser(array, startPosition);
    }

    public static final GlobalRequestFailureMessagePreparator PREPARATOR =
            new GlobalRequestFailureMessagePreparator();

    public static final GlobalRequestFailureMessageSerializer SERIALIZER =
            new GlobalRequestFailureMessageSerializer();
}
