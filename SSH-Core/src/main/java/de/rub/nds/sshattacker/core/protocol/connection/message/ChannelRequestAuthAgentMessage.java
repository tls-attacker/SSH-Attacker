/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestAuthAgentMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestAuthAgentMessage
        extends ChannelRequestMessage<ChannelRequestAuthAgentMessage> {

    public ChannelRequestAuthAgentMessage() {
        super(ChannelRequestType.AUTH_AGENT_REQ_OPENSSH_COM);
    }

    public ChannelRequestAuthAgentMessage(Integer senderChannel) {
        super(ChannelRequestType.SHELL, senderChannel);
    }

    @Override
    public ChannelRequestAuthAgentMessageHandler getHandler(SshContext context) {
        return new ChannelRequestAuthAgentMessageHandler(context, this);
    }
}
