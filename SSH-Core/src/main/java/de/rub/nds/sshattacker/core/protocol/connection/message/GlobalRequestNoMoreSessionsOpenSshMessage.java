/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestNoMoreSessionsOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestNoMoreSessionsOpenSshMessage
        extends GlobalRequestMessage<GlobalRequestNoMoreSessionsOpenSshMessage> {

    public GlobalRequestNoMoreSessionsOpenSshMessage() {
        super();
    }

    public GlobalRequestNoMoreSessionsOpenSshMessage(
            GlobalRequestNoMoreSessionsOpenSshMessage other) {
        super(other);
    }

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessage createCopy() {
        return new GlobalRequestNoMoreSessionsOpenSshMessage(this);
    }

    public static final GlobalRequestNoMoreSessionsOpenSshMessageHandler HANDLER =
            new GlobalRequestNoMoreSessionsOpenSshMessageHandler();

    @Override
    public GlobalRequestNoMoreSessionsOpenSshMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestNoMoreSessionsOpenSshMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestNoMoreSessionsOpenSshMessageHandler.SERIALIZER.serialize(this);
    }
}
