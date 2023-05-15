/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelFailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelFailureMessageHandler extends SshMessageHandler<ChannelFailureMessage> {

    public ChannelFailureMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelFailureMessageHandler(SshContext context, ChannelFailureMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelFailureMessage
    }

    @Override
    public ChannelFailureMessageParser getParser(byte[] array) {
        return new ChannelFailureMessageParser(array);
    }

    @Override
    public ChannelFailureMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelFailureMessageParser(array, startPosition);
    }

    @Override
    public ChannelFailureMessagePreparator getPreparator() {
        return new ChannelFailureMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelMessageSerializer<ChannelFailureMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
