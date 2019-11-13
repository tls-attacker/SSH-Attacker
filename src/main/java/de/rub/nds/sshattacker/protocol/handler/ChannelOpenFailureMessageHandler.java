package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenFailureMessageHandler extends Handler<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelOpenFailureMessage msg) {
    }

}
