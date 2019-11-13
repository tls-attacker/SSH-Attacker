package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenMessageHandler extends Handler<ChannelOpenMessage> {

    public ChannelOpenMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelOpenMessage msg) {
    }

}
