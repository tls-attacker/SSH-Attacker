package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ClientInitMessageHandler extends Handler<ClientInitMessage> {

    public ClientInitMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ClientInitMessage message) {
        context.setServerVersion(message.getVersion().getValue());
        context.setServerComment(message.getComment().getValue());
        context.appendToExchangeHashInput(context.getServerVersion().getBytes());
    }
}
