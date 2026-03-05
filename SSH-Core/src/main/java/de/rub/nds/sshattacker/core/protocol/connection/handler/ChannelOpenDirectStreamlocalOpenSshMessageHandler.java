/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenDirectStreamlocalOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenDirectStreamlocalOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenDirectStreamlocalOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenDirectStreamlocalOpenSshMessageHandler
        extends SshMessageHandler<ChannelOpenDirectStreamlocalOpenSshMessage> {

    @Override
    public void adjustContext(
            SshContext context, ChannelOpenDirectStreamlocalOpenSshMessage object) {
        // TODO: Handle ChannelOpenDirectStreamlocalOpenSshMessage
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageParser getParser(
            byte[] array, SshContext context) {
        return new ChannelOpenDirectStreamlocalOpenSshMessageParser(array);
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenDirectStreamlocalOpenSshMessageParser(array, startPosition);
    }

    public static final ChannelOpenDirectStreamlocalOpenSshMessagePreparator PREPARATOR =
            new ChannelOpenDirectStreamlocalOpenSshMessagePreparator();

    public static final ChannelOpenDirectStreamlocalOpenSshMessageSerializer SERIALIZER =
            new ChannelOpenDirectStreamlocalOpenSshMessageSerializer();
}
