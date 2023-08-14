/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEndOfWriteMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestEndOfWriteMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestEndOfWriteMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestEndOfWriteMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestEndOfWriteMessageHandler
        extends SshMessageHandler<ChannelRequestEndOfWriteMessage> {

    public ChannelRequestEndOfWriteMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestEndOfWriteMessageHandler(
            SshContext context, ChannelRequestEndOfWriteMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestEndOfWriteMessageParser getParser(byte[] array) {
        return new ChannelRequestEndOfWriteMessageParser(array);
    }

    @Override
    public ChannelRequestEndOfWriteMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestEndOfWriteMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestEndOfWriteMessagePreparator getPreparator() {
        return new ChannelRequestEndOfWriteMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestEndOfWriteMessageSerializer getSerializer() {
        return new ChannelRequestEndOfWriteMessageSerializer(message);
    }
}
