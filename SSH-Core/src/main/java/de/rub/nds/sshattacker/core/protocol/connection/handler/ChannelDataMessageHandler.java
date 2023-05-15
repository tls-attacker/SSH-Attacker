/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelDataMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessageHandler extends SshMessageHandler<ChannelDataMessage> {

    public ChannelDataMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelDataMessageHandler(SshContext context, ChannelDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelDataMessage
    }

    @Override
    public ChannelDataMessageParser getParser(byte[] array) {
        return new ChannelDataMessageParser(array);
    }

    @Override
    public ChannelDataMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelDataMessageParser(array, startPosition);
    }

    @Override
    public ChannelDataMessagePreparator getPreparator() {
        return new ChannelDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelDataMessageSerializer getSerializer() {
        return new ChannelDataMessageSerializer(message);
    }
}
