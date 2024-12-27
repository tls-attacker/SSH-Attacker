/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestAuthAgentMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestAuthAgentMessage
        extends ChannelRequestMessage<ChannelRequestAuthAgentMessage> {

    public ChannelRequestAuthAgentMessage() {
        super();
    }

    public ChannelRequestAuthAgentMessage(ChannelRequestAuthAgentMessage other) {
        super(other);
    }

    @Override
    public ChannelRequestAuthAgentMessage createCopy() {
        return new ChannelRequestAuthAgentMessage(this);
    }

    @Override
    public ChannelRequestAuthAgentMessageHandler getHandler(SshContext context) {
        return new ChannelRequestAuthAgentMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelRequestAuthAgentMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
