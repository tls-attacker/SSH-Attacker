package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ServiceRequestMessagePreparator extends Preparator<ServiceRequestMessage> {

    public ServiceRequestMessagePreparator(SshContext context, ServiceRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_SERVICE_REQUEST.id);
        message.setServiceName(context.getChooser().getServiceName());
    }

}
