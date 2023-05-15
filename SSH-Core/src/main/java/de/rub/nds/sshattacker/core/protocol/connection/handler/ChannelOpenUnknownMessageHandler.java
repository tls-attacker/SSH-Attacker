/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenUnknownMessageHandler extends SshMessageHandler<ChannelOpenUnknownMessage> {

    public ChannelOpenUnknownMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenUnknownMessageHandler(SshContext context, ChannelOpenUnknownMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelOpenUnknownMessageParser getParser(byte[] array) {
        return new ChannelOpenUnknownMessageParser(array);
    }

    @Override
    public ChannelOpenUnknownMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenUnknownMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenUnknownMessagePreparator getPreparator() {
        return new ChannelOpenUnknownMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenUnknownMessageSerializer getSerializer() {
        return new ChannelOpenUnknownMessageSerializer(message);
    }
}
