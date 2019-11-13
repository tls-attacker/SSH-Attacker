package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelSuccessMessageHandler extends Handler<ChannelSuccessMessage> {

    public ChannelSuccessMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelSuccessMessage msg) {
    }

}
