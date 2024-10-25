/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestAuthAgentMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestAuthAgentMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestAuthAgentMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestAuthAgentMessageSerializer;
import java.io.InputStream;

public class ChannelRequestAuthAgentMessage
        extends ChannelRequestMessage<ChannelRequestAuthAgentMessage> {

    @Override
    public ChannelRequestAuthAgentMessageHandler getHandler(SshContext context) {
        return new ChannelRequestAuthAgentMessageHandler(context);
    }

    @Override
    public ChannelRequestAuthAgentMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestAuthAgentMessageParser(stream);
    }

    @Override
    public ChannelRequestAuthAgentMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestAuthAgentMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestAuthAgentMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestAuthAgentMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "AUTH_AGENT";
    }
}
