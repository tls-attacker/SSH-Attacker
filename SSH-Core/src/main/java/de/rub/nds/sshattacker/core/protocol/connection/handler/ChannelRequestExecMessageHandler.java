/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExecMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExecMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestExecMessageHandler extends SshMessageHandler<ChannelRequestExecMessage> {

    public ChannelRequestExecMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestExecMessageHandler(SshContext context, ChannelRequestExecMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestExecMessage
    }

    @Override
    public SshMessageParser<ChannelRequestExecMessage> getParser(byte[] array, int startPosition) {
        throw new NotImplementedException("ChannelRequestExecMessageHandler::getParser");
    }

    @Override
    public ChannelRequestExecMessagePreparator getPreparator() {
        return new ChannelRequestExecMessagePreparator(context, message);
    }

    @Override
    public ChannelRequestExecMessageSerializer getSerializer() {
        return new ChannelRequestExecMessageSerializer(message);
    }
}
