package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ClientInitMessageHandler extends Handler<ClientInitMessage> {

    public ClientInitMessageHandler(SshContext context, ClientInitMessage message) {
        super(context, message);
    }
    @Override
    public void handle() {
        context.setServerVersion(message.getVersion().getValue());
        context.setServerComment(message.getComment().getValue());
        context.appendToExchangeHashInput(context.getServerVersion().getBytes());
    }

}
