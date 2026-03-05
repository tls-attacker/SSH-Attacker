/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestAuthAgentReqOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestAuthAgentReqOpenSshMessage
        extends ChannelRequestMessage<ChannelRequestAuthAgentReqOpenSshMessage>
        implements HasSentHandler {

    public ChannelRequestAuthAgentReqOpenSshMessage() {
        super();
    }

    public ChannelRequestAuthAgentReqOpenSshMessage(
            ChannelRequestAuthAgentReqOpenSshMessage other) {
        super(other);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessage createCopy() {
        return new ChannelRequestAuthAgentReqOpenSshMessage(this);
    }

    public static final ChannelRequestAuthAgentReqOpenSshMessageHandler HANDLER =
            new ChannelRequestAuthAgentReqOpenSshMessageHandler();

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageHandler getHandler() {
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
        ChannelRequestAuthAgentReqOpenSshMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestAuthAgentReqOpenSshMessageHandler.SERIALIZER.serialize(this);
    }
}
