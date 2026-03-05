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

    @Override
    public void adjustContext(
            SshContext context, GlobalRequestNoMoreSessionsOpenSshMessage object) {}

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageParser getParser(
            byte[] array, SshContext context) {
        return new GlobalRequestNoMoreSessionsOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestNoMoreSessionsOpenSshMessageParser(array, startPosition);
    }

    public static final GlobalRequestNoMoreSessionsOpenSshMessagePreparator PREPARATOR =
            new GlobalRequestNoMoreSessionsOpenSshMessagePreparator();

    public static final GlobalRequestNoMoreSessionsOpenSshMessageSerializer SERIALIZER =
            new GlobalRequestNoMoreSessionsOpenSshMessageSerializer();
}
