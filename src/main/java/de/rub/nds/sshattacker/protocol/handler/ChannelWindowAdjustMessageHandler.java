package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelWindowAdjustMessageHandler extends Handler<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelWindowAdjustMessage msg) {
    }

}
