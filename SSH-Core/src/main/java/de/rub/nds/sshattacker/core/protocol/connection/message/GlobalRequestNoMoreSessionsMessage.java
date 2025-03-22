/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestNoMoreSessionsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestNoMoreSessionsMessage
        extends GlobalRequestMessage<GlobalRequestNoMoreSessionsMessage> {

    public GlobalRequestNoMoreSessionsMessage() {
        super();
    }

    public GlobalRequestNoMoreSessionsMessage(GlobalRequestNoMoreSessionsMessage other) {
        super(other);
    }

    @Override
    public GlobalRequestNoMoreSessionsMessage createCopy() {
        return new GlobalRequestNoMoreSessionsMessage(this);
    }

    public static final GlobalRequestNoMoreSessionsMessageHandler HANDLER =
            new GlobalRequestNoMoreSessionsMessageHandler();

    @Override
    public GlobalRequestNoMoreSessionsMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestNoMoreSessionsMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestNoMoreSessionsMessageHandler.SERIALIZER.serialize(this);
    }
}
