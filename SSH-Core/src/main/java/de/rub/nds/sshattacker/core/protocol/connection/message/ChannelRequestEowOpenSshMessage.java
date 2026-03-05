/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestEowOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestEowOpenSshMessage
        extends ChannelRequestMessage<ChannelRequestEowOpenSshMessage> implements HasSentHandler {

    public ChannelRequestEowOpenSshMessage() {
        super();
    }

    public ChannelRequestEowOpenSshMessage(ChannelRequestEowOpenSshMessage other) {
        super(other);
    }

    @Override
    public ChannelRequestEowOpenSshMessage createCopy() {
        return new ChannelRequestEowOpenSshMessage(this);
    }

    public static final ChannelRequestEowOpenSshMessageHandler HANDLER =
            new ChannelRequestEowOpenSshMessageHandler();

    @Override
    public ChannelRequestEowOpenSshMessageHandler getHandler() {
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
        ChannelRequestEowOpenSshMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestEowOpenSshMessageHandler.SERIALIZER.serialize(this);
    }
}
