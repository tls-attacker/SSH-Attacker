package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenConfirmationMessageHandler extends Handler<ChannelOpenConfirmationMessage>{

    public ChannelOpenConfirmationMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelOpenConfirmationMessage msg) {
    }

}
