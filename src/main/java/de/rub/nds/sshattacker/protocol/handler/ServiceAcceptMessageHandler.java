package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceAcceptMessageHandler extends Handler<ServiceAcceptMessage> {

    public ServiceAcceptMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ServiceAcceptMessage msg) {
    }

}
