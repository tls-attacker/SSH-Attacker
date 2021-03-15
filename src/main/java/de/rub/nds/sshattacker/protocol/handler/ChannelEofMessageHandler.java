package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelEofMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelEofMessageHandler extends Handler<ChannelEofMessage> {

    public ChannelEofMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelEofMessage msg) {
    }

}
