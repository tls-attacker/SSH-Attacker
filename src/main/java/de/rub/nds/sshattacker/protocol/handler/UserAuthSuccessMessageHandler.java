package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthSuccessMessageHandler extends Handler<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserAuthSuccessMessage msg) {
    }

}
