package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class IgnoreMessageHandler extends Handler<IgnoreMessage> {

    public IgnoreMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(IgnoreMessage msg) {
    }

}
