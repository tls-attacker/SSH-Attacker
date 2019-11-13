package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthSuccessMessagePreparator extends Preparator<UserAuthSuccessMessage> {

    public UserAuthSuccessMessagePreparator(SshContext context, UserAuthSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_SUCCESS.id);
    }

}
