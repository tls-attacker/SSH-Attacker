package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.UnimplementedMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UnimplementedMessageHandler extends Handler<UnimplementedMessage> {

    public UnimplementedMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UnimplementedMessage msg) {
    }

}
