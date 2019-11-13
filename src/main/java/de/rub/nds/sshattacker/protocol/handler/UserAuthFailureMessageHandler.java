package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthFailureMessageHandler extends Handler<UserAuthFailureMessage> {

    public UserAuthFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserAuthFailureMessage msg) {
    }

}
