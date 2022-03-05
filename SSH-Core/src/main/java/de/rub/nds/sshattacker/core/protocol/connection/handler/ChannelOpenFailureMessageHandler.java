/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenFailureMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenFailureMessageHandler extends SshMessageHandler<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenFailureMessageHandler(SshContext context, ChannelOpenFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelOpenFailureMessage
        Channel channel = context.getChannels().get(message.getRecipientChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException(
                    "Can't find the required channel of the received message!");
        } else {
            channel.setOpen(false);
        }
    }

    @Override
    public ChannelOpenFailureMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenFailureMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenFailureMessagePreparator getPreparator() {
        return new ChannelOpenFailureMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenFailureMessageSerializer getSerializer() {
        return new ChannelOpenFailureMessageSerializer(message);
    }
}
