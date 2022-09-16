/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestUnknownMessageHandler
        extends SshMessageHandler<ChannelRequestUnknownMessage> {

    public ChannelRequestUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestUnknownMessageHandler(
            SshContext context, ChannelRequestUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelRequestUnknownMessageParser getParser(byte[] array) {
        return new ChannelRequestUnknownMessageParser(array);
    }

    @Override
    public ChannelRequestUnknownMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestUnknownMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestUnknownMessagePreparator getPreparator() {
        return new ChannelRequestUnknownMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestUnknownMessageSerializer getSerializer() {
        return new ChannelRequestUnknownMessageSerializer(message);
    }
}
