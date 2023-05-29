/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;

public class ChannelSuccessMessageHandler extends SshMessageHandler<ChannelSuccessMessage> {

    public ChannelSuccessMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelSuccessMessageHandler(SshContext context, ChannelSuccessMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ChannelSuccessMessage message) {
        // TODO: Handle ChannelSuccessMessage
    }

    /*@Override
    public SshMessageParser<ChannelSuccessMessage> getParser(byte[] array) {
        return new ChannelSuccessMessageParser(array);
    }

    @Override
    public SshMessageParser<ChannelSuccessMessage> getParser(byte[] array, int startPosition) {
        return new ChannelSuccessMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<ChannelSuccessMessage> getPreparator() {
        return new ChannelSuccessMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<ChannelSuccessMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }*/
}
