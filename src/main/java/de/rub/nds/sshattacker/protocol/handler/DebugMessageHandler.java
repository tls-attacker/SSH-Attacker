package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.DebugMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class DebugMessageHandler extends Handler<DebugMessage> {

    public DebugMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DebugMessage msg) {
    }

}
