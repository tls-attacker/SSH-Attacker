/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelEofMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelEofMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import java.io.InputStream;

public class ChannelEofMessage extends ChannelMessage<ChannelEofMessage> {

    @Override
    public ChannelEofMessageHandler getHandler(SshContext context) {
        return new ChannelEofMessageHandler(context);
    }

    @Override
    public ChannelEofMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelEofMessageParser(stream);
    }

    @Override
    public ChannelEofMessagePreparator getPreparator(SshContext context) {
        return new ChannelEofMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelMessageSerializer<ChannelEofMessage> getSerializer(SshContext context) {
        return new ChannelMessageSerializer<>(this);
    }

    @Override
    public String toShortString() {
        return "CHAN_EOF";
    }
}
