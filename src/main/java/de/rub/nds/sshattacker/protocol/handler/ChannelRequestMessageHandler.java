package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelRequestMessageHandler extends Handler<ChannelRequestMessage> {

    public ChannelRequestMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelRequestMessage msg) {
    }

}
