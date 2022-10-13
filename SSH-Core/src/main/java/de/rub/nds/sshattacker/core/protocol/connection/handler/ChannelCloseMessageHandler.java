/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.exceptions.MissingChannelException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelCloseMessageHandler extends SshMessageHandler<ChannelCloseMessage> {

    public ChannelCloseMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelCloseMessageHandler(SshContext context, ChannelCloseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelCloseMessage
        Channel channel = context.getChannels().get(message.getRecipientChannel().getValue());
        if (channel == null) {
            throw new MissingChannelException(
                    "Can't find the required channel of the received message!");
        } else if (channel.isOpen().getValue()) {
            if (channel.getFirstCloseMessage().getValue()) {
                channel.setOpen(false);
            } else {
                channel.setFirstCloseMessage(true);
            }
        } else {
            LOGGER.warn("Required channel is closed!");
            // throw new MissingChannelException("Required channel is closed!");
        }
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array) {
        return new ChannelCloseMessageParser(array);
    }

    @Override
    public ChannelCloseMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelCloseMessageParser(array, startPosition);
    }

    @Override
    public ChannelCloseMessagePreparator getPreparator() {
        return new ChannelCloseMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelMessageSerializer<ChannelCloseMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
