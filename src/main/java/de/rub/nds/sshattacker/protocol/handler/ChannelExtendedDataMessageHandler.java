package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelExtendedDataMessageHandler extends Handler<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelExtendedDataMessage msg) {
    }

}
