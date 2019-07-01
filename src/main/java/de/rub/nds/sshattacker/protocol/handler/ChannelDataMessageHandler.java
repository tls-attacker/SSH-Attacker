package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelDataMessageHandler extends Handler<ChannelDataMessage> {

    public ChannelDataMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelDataMessage msg) {
    }
}
