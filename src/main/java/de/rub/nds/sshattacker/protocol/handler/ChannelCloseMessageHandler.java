package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelCloseMessageHandler extends Handler<ChannelCloseMessage> {

    public ChannelCloseMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelCloseMessage msg) {
    }

}
