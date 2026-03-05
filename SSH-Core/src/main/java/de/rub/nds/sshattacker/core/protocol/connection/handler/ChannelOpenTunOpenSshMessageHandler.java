/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenTunOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenTunOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenTunOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenTunOpenSshMessageHandler
        extends SshMessageHandler<ChannelOpenTunOpenSshMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelOpenTunOpenSshMessage object) {
        // TODO: Handle ChannelOpenTunOpenSshMessage
    }

    @Override
    public ChannelOpenTunOpenSshMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenTunOpenSshMessageParser(array);
    }

    @Override
    public ChannelOpenTunOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenTunOpenSshMessageParser(array, startPosition);
    }

    public static final ChannelOpenTunOpenSshMessagePreparator PREPARATOR =
            new ChannelOpenTunOpenSshMessagePreparator();

    public static final ChannelOpenTunOpenSshMessageSerializer SERIALIZER =
            new ChannelOpenTunOpenSshMessageSerializer();
}
