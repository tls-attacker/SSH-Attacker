/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDefaultMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenDefaultMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenDefaultMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenDefaultMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenDefaultMessageHandler extends SshMessageHandler<ChannelOpenDefaultMessage> {
    public ChannelOpenDefaultMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenDefaultMessageHandler(SshContext context, ChannelOpenDefaultMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelOpenDefaultMessageParser getParser(byte[] array) {
        return new ChannelOpenDefaultMessageParser(array);
    }

    @Override
    public ChannelOpenDefaultMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenDefaultMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenDefaultMessagePreperator getPreparator() {
        return new ChannelOpenDefaultMessagePreperator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenDefaultMessageSerializer getSerializer() {
        return new ChannelOpenDefaultMessageSerializer(message);
    }
}
