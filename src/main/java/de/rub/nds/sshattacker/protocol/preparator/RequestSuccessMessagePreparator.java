package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.RequestSuccessMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestSuccessMessagePreparator extends Preparator<RequestSuccessMessage> {

    public RequestSuccessMessagePreparator(SshContext context, RequestSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS.id);
    }

}
