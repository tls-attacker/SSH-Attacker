/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenSessionMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenSessionMessage extends ChannelOpenMessage<ChannelOpenSessionMessage> {

    public ChannelOpenSessionMessage() {
        super();
    }

    public ChannelOpenSessionMessage(int localChannelId) {
        super();
        setConfigLocalChannelId(localChannelId);
    }

    public ChannelOpenSessionMessage(ChannelOpenSessionMessage other) {
        super(other);
    }

    @Override
    public ChannelOpenSessionMessage createCopy() {
        return new ChannelOpenSessionMessage(this);
    }

    public static final ChannelOpenSessionMessageHandler HANDLER =
            new ChannelOpenSessionMessageHandler();

    @Override
    public ChannelOpenSessionMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenSessionMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelOpenSessionMessageHandler.SERIALIZER.serialize(this);
    }
}
