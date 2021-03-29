package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.ChannelSuccessMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelSuccessMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelSuccessMessage extends Message {

    @Override
    public Handler getHandler(SshContext context) {
        return new ChannelSuccessMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelSuccessMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelSuccessMessagePreparator(context, this);
    }

}
