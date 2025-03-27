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

    public ChannelOpenDirectStreamlocalOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenDirectStreamlocalOpenSshMessageHandler(
            SshContext context, ChannelOpenDirectStreamlocalOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelOpenDirectStreamlocalOpenSshMessage
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageParser getParser(byte[] array) {
        return new ChannelOpenDirectStreamlocalOpenSshMessageParser(array);
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new ChannelOpenDirectStreamlocalOpenSshMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessagePreparator getPreparator() {
        return new ChannelOpenDirectStreamlocalOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public ChannelOpenDirectStreamlocalOpenSshMessageSerializer getSerializer() {
        return new ChannelOpenDirectStreamlocalOpenSshMessageSerializer(message);
    }
}
