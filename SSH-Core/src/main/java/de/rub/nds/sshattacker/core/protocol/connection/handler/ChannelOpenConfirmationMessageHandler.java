/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessageHandler
        extends SshMessageHandler<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenConfirmationMessageHandler(
            SshContext context, ChannelOpenConfirmationMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.setRemoteChannel(message.getSenderChannel().getValue());
        // TODO: Set window and packet size for outgoing packets
    }

    @Override
    public ChannelOpenConfirmationMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenConfirmationMessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenConfirmationMessagePreparator getPreparator() {
        return new ChannelOpenConfirmationMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenConfirmationMessageSerializer getSerializer() {
        return new ChannelOpenConfirmationMessageSerializer(message);
    }
}
