package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientInitMessagePreparator extends Preparator<ClientInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientInitMessagePreparator(SshContext context, ClientInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setVersion(context.getClientVersion());
        message.setComment(context.getClientComment());
    }
}
