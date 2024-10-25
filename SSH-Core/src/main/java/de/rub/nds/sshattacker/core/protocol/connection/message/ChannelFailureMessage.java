/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelFailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import java.io.InputStream;

public class ChannelFailureMessage extends ChannelMessage<ChannelFailureMessage> {

    @Override
    public ChannelFailureMessageHandler getHandler(SshContext context) {
        return new ChannelFailureMessageHandler(context);
    }

    @Override
    public ChannelFailureMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelFailureMessageParser(stream);
    }

    @Override
    public ChannelFailureMessagePreparator getPreparator(SshContext context) {
        return new ChannelFailureMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelMessageSerializer<ChannelFailureMessage> getSerializer(SshContext context) {
        return new ChannelMessageSerializer<>(this);
    }

    @Override
    public String toShortString() {
        return "CHAN_FAIL";
    }
}
