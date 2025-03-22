/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class NewKeysMessage extends SshMessage<NewKeysMessage> implements HasSentHandler {

    public NewKeysMessage() {
        super();
    }

    public NewKeysMessage(NewKeysMessage other) {
        super(other);
    }

    @Override
    public NewKeysMessage createCopy() {
        return new NewKeysMessage(this);
    }

    public static final NewKeysMessageHandler HANDLER = new NewKeysMessageHandler();

    @Override
    public NewKeysMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        NewKeysMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return NewKeysMessageHandler.SERIALIZER.serialize(this);
    }
}
