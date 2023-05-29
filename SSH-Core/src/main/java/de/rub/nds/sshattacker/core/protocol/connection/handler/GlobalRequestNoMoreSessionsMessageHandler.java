/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsMessage;

public class GlobalRequestNoMoreSessionsMessageHandler
        extends SshMessageHandler<GlobalRequestNoMoreSessionsMessage> {

    public GlobalRequestNoMoreSessionsMessageHandler(SshContext context) {
        super(context);
    }

    /*public GlobalRequestNoMoreSessionsMessageHandler(
            SshContext context, GlobalRequestNoMoreSessionsMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(GlobalRequestNoMoreSessionsMessage message) {}

    /*@Override
    public GlobalRequestNoMoreSessionsMessageParser getParser(byte[] array) {
        return new GlobalRequestNoMoreSessionsMessageParser(array);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessageParser getParser(byte[] array, int startPosition) {
        return new GlobalRequestNoMoreSessionsMessageParser(array, startPosition);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessagePreparator getPreparator() {
        return new GlobalRequestNoMoreSessionsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessageSerializer getSerializer() {
        return new GlobalRequestNoMoreSessionsMessageSerializer(message);
    }*/
}
