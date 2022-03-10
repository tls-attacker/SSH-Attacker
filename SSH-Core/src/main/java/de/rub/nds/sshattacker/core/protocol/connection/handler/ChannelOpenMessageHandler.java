/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenMessageHandler extends SshMessageHandler<ChannelOpenMessage> {

    public ChannelOpenMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenMessageHandler(SshContext context, ChannelOpenMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelOpenMessage
        // ToDO implement system of own channel management for running as server
    }

    @Override
    public ChannelOpenMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenMessagePreparator getPreparator() {
        return new ChannelOpenMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenMessageSerializer getSerializer() {
        return new ChannelOpenMessageSerializer(message);
    }
}
