/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelFailureMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelFailureMessage extends ChannelMessage<ChannelFailureMessage> {

    public ChannelFailureMessage() {
        super();
    }

    public ChannelFailureMessage(ChannelFailureMessage other) {
        super(other);
    }

    @Override
    public ChannelFailureMessage createCopy() {
        return new ChannelFailureMessage(this);
    }

    public static final ChannelFailureMessageHandler HANDLER = new ChannelFailureMessageHandler();

    @Override
    public ChannelFailureMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelFailureMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelFailureMessageHandler.SERIALIZER.serialize(this);
    }
}
