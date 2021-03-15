package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserauthPasswordMessageHandler extends Handler<UserauthPasswordMessage> {

    public UserauthPasswordMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserauthPasswordMessage msg) {
    }

}
