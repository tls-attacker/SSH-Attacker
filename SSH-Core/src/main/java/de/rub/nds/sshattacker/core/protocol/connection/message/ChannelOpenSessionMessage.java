/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenSessionMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenSessionMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenSessionMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenSessionMessageSerializer;
import java.io.InputStream;

public class ChannelOpenSessionMessage extends ChannelOpenMessage<ChannelOpenSessionMessage> {
    @Override
    public ChannelOpenSessionMessageHandler getHandler(SshContext context) {
        return new ChannelOpenSessionMessageHandler(context);
    }

    @Override
    public ChannelOpenSessionMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelOpenSessionMessageParser(stream);
    }

    @Override
    public ChannelOpenSessionMessagePreperator getPreparator(SshContext context) {
        return new ChannelOpenSessionMessagePreperator(context.getChooser(), this);
    }

    @Override
    public ChannelOpenSessionMessageSerializer getSerializer(SshContext context) {
        return new ChannelOpenSessionMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "OEPN_SESSION";
    }
}
