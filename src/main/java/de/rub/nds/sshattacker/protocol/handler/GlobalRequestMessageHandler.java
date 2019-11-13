package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class GlobalRequestMessageHandler extends Handler<GlobalRequestMessage> {

    public GlobalRequestMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(GlobalRequestMessage msg) {
    }

}
