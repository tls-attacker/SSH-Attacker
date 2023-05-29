/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestShellMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestShellMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestShellMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestShellMessageSerializer;
import java.io.InputStream;

public class ChannelRequestShellMessage extends ChannelRequestMessage<ChannelRequestShellMessage> {

    @Override
    public ChannelRequestShellMessageHandler getHandler(SshContext context) {
        return new ChannelRequestShellMessageHandler(context);
    }

    @Override
    public ChannelRequestShellMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestShellMessageParser(stream);
    }

    @Override
    public ChannelRequestShellMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestShellMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestShellMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestShellMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "REQ_SHELL";
    }
}
