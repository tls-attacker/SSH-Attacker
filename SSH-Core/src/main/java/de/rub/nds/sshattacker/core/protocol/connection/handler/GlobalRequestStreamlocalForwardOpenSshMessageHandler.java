/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestStreamlocalForwardOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestStreamlocalForwardOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestStreamlocalForwardOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestStreamlocalForwardOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestStreamlocalForwardOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestStreamlocalForwardOpenSshMessage> {

    public GlobalRequestStreamlocalForwardOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public GlobalRequestStreamlocalForwardOpenSshMessageHandler(
            SshContext context, GlobalRequestStreamlocalForwardOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle GlobalRequestStreamlocalForwardOpenSshMessage
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessageParser getParser(byte[] array) {
        return new GlobalRequestStreamlocalForwardOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new GlobalRequestStreamlocalForwardOpenSshMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessagePreparator getPreparator() {
        return new GlobalRequestStreamlocalForwardOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public GlobalRequestStreamlocalForwardOpenSshMessageSerializer getSerializer() {
        return new GlobalRequestStreamlocalForwardOpenSshMessageSerializer(message);
    }
}
