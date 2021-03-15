package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelFailureMessageHandler extends Handler<ChannelFailureMessage> {

    public ChannelFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelFailureMessage msg) {
    }

}
