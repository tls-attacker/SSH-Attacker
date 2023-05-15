/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenSessionMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenSessionMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenSessionMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenSessionMessageHandler extends SshMessageHandler<ChannelOpenSessionMessage> {
    public ChannelOpenSessionMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenSessionMessageHandler(SshContext context, ChannelOpenSessionMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelOpenSessionMessageParser getParser(byte[] array) {
        return new ChannelOpenSessionMessageParser(array);
    }

    @Override
    public ChannelOpenSessionMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenSessionMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenSessionMessagePreperator getPreparator() {
        return new ChannelOpenSessionMessagePreperator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenSessionMessageSerializer getSerializer() {
        return new ChannelOpenSessionMessageSerializer(message);
    }
}
