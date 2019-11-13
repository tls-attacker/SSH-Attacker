package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.RequestFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestFailureMessagePreparator extends Preparator<RequestFailureMessage> {

    public RequestFailureMessagePreparator(SshContext context, RequestFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_REQUEST_FAILURE.id);
    }

}
