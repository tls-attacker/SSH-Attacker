package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserauthPasswordMessagePreparator extends Preparator<UserauthPasswordMessage> {

    public UserauthPasswordMessagePreparator(SshContext context, UserauthPasswordMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setUsername(context.getChooser().getUsername());
        message.setPassword(context.getChooser().getPassword());
        message.setServicename("ssh-connection");
        message.setExpectResponse(context.getChooser().getReplyWanted());
    }

}
