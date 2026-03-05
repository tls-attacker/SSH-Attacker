/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelEofMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelEofMessage extends ChannelMessage<ChannelEofMessage> {

    public ChannelEofMessage() {
        super();
    }

    public ChannelEofMessage(ChannelEofMessage other) {
        super(other);
    }

    @Override
    public ChannelEofMessage createCopy() {
        return new ChannelEofMessage(this);
    }

    public static final ChannelEofMessageHandler HANDLER = new ChannelEofMessageHandler();

    @Override
    public ChannelEofMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelEofMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelEofMessageHandler.SERIALIZER.serialize(this);
    }
}
