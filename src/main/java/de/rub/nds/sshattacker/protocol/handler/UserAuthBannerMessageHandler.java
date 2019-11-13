package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthBannerMessageHandler extends Handler<UserAuthBannerMessage> {

    public UserAuthBannerMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserAuthBannerMessage msg) {
    }

}
