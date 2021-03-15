package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class NewKeysMessageHandler extends Handler<NewKeysMessage> {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(NewKeysMessage msg) {
    }

}
