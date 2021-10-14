/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelSuccessMessageHandler extends SshMessageHandler<ChannelSuccessMessage> {

    public ChannelSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelSuccessMessageHandler(SshContext context, ChannelSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelSuccessMessage
    }

    @Override
    public SshMessageParser<ChannelSuccessMessage> getParser(byte[] array, int startPosition) {
        return new ChannelSuccessMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<ChannelSuccessMessage> getPreparator() {
        return new ChannelSuccessMessagePreparator(context, message);
    }

    @Override
    public SshMessageSerializer<ChannelSuccessMessage> getSerializer() {
        return new ChannelMessageSerializer<>(message);
    }
}
