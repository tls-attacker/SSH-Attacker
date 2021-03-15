package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessageHandler extends Handler<ServiceRequestMessage> {

    public ServiceRequestMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ServiceRequestMessage msg) {
    }

}
