/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelExtendedDataMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelExtendedDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelExtendedDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelExtendedDataMessageHandler
        extends SshMessageHandler<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelExtendedDataMessageHandler(
            SshContext context, ChannelExtendedDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelExtendedDataMessage
    }

    @Override
    public ChannelExtendedDataMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelExtendedDataMessageParser(array, startPosition);
    }

    @Override
    public ChannelExtendedDataMessagePreparator getPreparator() {
        return new ChannelExtendedDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelExtendedDataMessageSerializer getSerializer() {
        return new ChannelExtendedDataMessageSerializer(message);
    }
}
