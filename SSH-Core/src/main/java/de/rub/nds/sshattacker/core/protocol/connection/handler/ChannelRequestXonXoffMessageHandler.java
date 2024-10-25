/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestXonXoffMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestXonXoffMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestXonXoffMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestXonXoffMessageHandler
        extends SshMessageHandler<ChannelRequestXonXoffMessage> {

    public ChannelRequestXonXoffMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestXonXoffMessageHandler(
            SshContext context, ChannelRequestXonXoffMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestXonXoffMessageParser getParser(byte[] array) {
        return new ChannelRequestXonXoffMessageParser(array);
    }

    @Override
    public ChannelRequestXonXoffMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestXonXoffMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestXonXoffMessagePreparator getPreparator() {
        return new ChannelRequestXonXoffMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestXonXoffMessageSerializer getSerializer() {
        return new ChannelRequestXonXoffMessageSerializer(message);
    }
}
