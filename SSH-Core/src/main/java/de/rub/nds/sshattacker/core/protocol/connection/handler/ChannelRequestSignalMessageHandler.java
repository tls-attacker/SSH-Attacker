/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestSignalMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestSignalMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestSignalMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestSignalMessageHandler
        extends SshMessageHandler<ChannelRequestSignalMessage> {

    public ChannelRequestSignalMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestSignalMessageHandler(
            SshContext context, ChannelRequestSignalMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelRequestSignalMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestSignalMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestSignalMessagePreperator getPreparator() {
        return new ChannelRequestSignalMessagePreperator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestSignalMessageSerializer getSerializer() {
        return new ChannelRequestSignalMessageSerializer(message);
    }
}
