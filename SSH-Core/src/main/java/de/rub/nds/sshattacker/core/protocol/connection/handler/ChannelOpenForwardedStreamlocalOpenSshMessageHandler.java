/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedStreamlocalOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenForwardedStreamlocalOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenForwardedStreamlocalOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenForwardedStreamlocalOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenForwardedStreamlocalOpenSshMessageHandler
        extends SshMessageHandler<ChannelOpenForwardedStreamlocalOpenSshMessage> {

    public ChannelOpenForwardedStreamlocalOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenForwardedStreamlocalOpenSshMessageHandler(
            SshContext context, ChannelOpenForwardedStreamlocalOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelOpenForwardedStreamlocalOpenSshMessage
    }

    @Override
    public ChannelOpenForwardedStreamlocalOpenSshMessageParser getParser(byte[] array) {
        return new ChannelOpenForwardedStreamlocalOpenSshMessageParser(array);
    }

    @Override
    public ChannelOpenForwardedStreamlocalOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new ChannelOpenForwardedStreamlocalOpenSshMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenForwardedStreamlocalOpenSshMessagePreparator getPreparator() {
        return new ChannelOpenForwardedStreamlocalOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public ChannelOpenForwardedStreamlocalOpenSshMessageSerializer getSerializer() {
        return new ChannelOpenForwardedStreamlocalOpenSshMessageSerializer(message);
    }
}
