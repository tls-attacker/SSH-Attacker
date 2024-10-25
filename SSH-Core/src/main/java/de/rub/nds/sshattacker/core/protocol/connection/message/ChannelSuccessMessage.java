/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import java.io.InputStream;

public class ChannelSuccessMessage extends ChannelMessage<ChannelSuccessMessage> {

    @Override
    public ChannelSuccessMessageHandler getHandler(SshContext context) {
        return new ChannelSuccessMessageHandler(context);
    }

    @Override
    public SshMessageParser<ChannelSuccessMessage> getParser(
            SshContext context, InputStream stream) {
        return new ChannelSuccessMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<ChannelSuccessMessage> getPreparator(SshContext context) {
        return new ChannelSuccessMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ChannelSuccessMessage> getSerializer(SshContext context) {
        return new ChannelMessageSerializer<>(this);
    }

    @Override
    public String toShortString() {
        return "CH_SUCCESS";
    }
}
