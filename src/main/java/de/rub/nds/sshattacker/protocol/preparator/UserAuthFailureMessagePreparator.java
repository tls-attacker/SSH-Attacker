package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthFailureMessagePreparator extends Preparator<UserAuthFailureMessage> {

    public UserAuthFailureMessagePreparator(SshContext context, UserAuthFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_FAILURE.id);
    }

}
