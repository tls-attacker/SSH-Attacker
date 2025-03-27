/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEowOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestEowOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestEowOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestEowOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestEowOpenSshMessageHandler
        extends SshMessageHandler<ChannelRequestEowOpenSshMessage> {

    public ChannelRequestEowOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestEowOpenSshMessageHandler(
            SshContext context, ChannelRequestEowOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestEowOpenSshMessage
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestEowOpenSshMessageParser getParser(byte[] array) {
        return new ChannelRequestEowOpenSshMessageParser(array);
    }

    @Override
    public ChannelRequestEowOpenSshMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestEowOpenSshMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestEowOpenSshMessagePreparator getPreparator() {
        return new ChannelRequestEowOpenSshMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestEowOpenSshMessageSerializer getSerializer() {
        return new ChannelRequestEowOpenSshMessageSerializer(message);
    }
}
