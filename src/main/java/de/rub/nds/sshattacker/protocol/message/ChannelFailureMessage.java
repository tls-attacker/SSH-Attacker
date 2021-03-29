package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.ChannelFailureMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelFailureMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelFailureMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelFailureMessage extends Message {

    @Override
    public Handler getHandler(SshContext context) {
        return new ChannelFailureMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelFailureMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelFailureMessagePreparator(context, this);
    }

}
