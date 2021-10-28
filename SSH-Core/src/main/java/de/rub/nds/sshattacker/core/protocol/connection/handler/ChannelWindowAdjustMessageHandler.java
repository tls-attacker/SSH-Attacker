/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessageHandler
        extends SshMessageHandler<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelWindowAdjustMessageHandler(
            SshContext context, ChannelWindowAdjustMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelWindowAdjustMessageHandler
    }

    @Override
    public ChannelWindowAdjustMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelWindowAdjustMessageParser(array, startPosition);
    }

    @Override
    public ChannelWindowAdjustMessagePreparator getPreparator() {
        return new ChannelWindowAdjustMessagePreparator(context, message);
    }

    @Override
    public ChannelWindowAdjustMessageSerializer getSerializer() {
        return new ChannelWindowAdjustMessageSerializer(message);
    }
}
