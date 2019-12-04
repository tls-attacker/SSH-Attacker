package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceAcceptMessagePreparator extends Preparator<ServiceAcceptMessage> {

    public ServiceAcceptMessagePreparator(SshContext context, ServiceAcceptMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_SERVICE_ACCEPT.id);
        message.setServiceName("");
    }

}
