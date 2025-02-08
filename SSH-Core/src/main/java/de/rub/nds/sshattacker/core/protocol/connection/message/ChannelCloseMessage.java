/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelCloseMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelCloseMessage extends ChannelMessage<ChannelCloseMessage>
        implements HasSentHandler {

    public ChannelCloseMessage() {
        super();
    }

    public ChannelCloseMessage(int localChannelId) {
        super();
        setConfigLocalChannelId(localChannelId);
    }

    public ChannelCloseMessage(ChannelCloseMessage other) {
        super(other);
    }

    @Override
    public ChannelCloseMessage createCopy() {
        return new ChannelCloseMessage(this);
    }

    public static final ChannelCloseMessageHandler HANDLER = new ChannelCloseMessageHandler();

    @Override
    public ChannelCloseMessageHandler getHandler() {
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
        ChannelCloseMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelCloseMessageHandler.SERIALIZER.serialize(this);
    }
}
