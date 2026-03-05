/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelDataMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessageHandler extends SshMessageHandler<ChannelDataMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelDataMessage object) {}

    @Override
    public ChannelDataMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelDataMessageParser(array);
    }

    @Override
    public ChannelDataMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new ChannelDataMessageParser(array, startPosition);
    }

    public static final ChannelDataMessagePreparator PREPARATOR =
            new ChannelDataMessagePreparator();

    public static final ChannelDataMessageSerializer SERIALIZER =
            new ChannelDataMessageSerializer();
}
