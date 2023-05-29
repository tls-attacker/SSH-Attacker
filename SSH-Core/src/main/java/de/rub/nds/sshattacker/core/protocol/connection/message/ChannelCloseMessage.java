/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelCloseMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import java.io.InputStream;

public class ChannelCloseMessage extends ChannelMessage<ChannelCloseMessage> {

    @Override
    public ChannelCloseMessageHandler getHandler(SshContext context) {
        return new ChannelCloseMessageHandler(context);
    }

    @Override
    public ChannelCloseMessagePreparator getPreparator(SshContext sshContext) {
        return new ChannelCloseMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public ChannelMessageSerializer<ChannelCloseMessage> getSerializer(SshContext sshContext) {
        return new ChannelMessageSerializer<>(this);
    }

    @Override
    public ChannelCloseMessageParser getParser(SshContext sshContext, InputStream stream) {
        return new ChannelCloseMessageParser(stream);
    }

    @Override
    public String toShortString() {
        return "CHAN_CLOSE";
    }
}
