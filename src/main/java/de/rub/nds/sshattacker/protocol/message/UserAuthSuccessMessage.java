package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.UserAuthSuccessMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.UserAuthSuccessMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.protocol.serializer.UserAuthSuccessMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthSuccessMessage extends Message {

    @Override
    public Handler getHandler(SshContext context) {
        return new UserAuthSuccessMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new UserAuthSuccessMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new UserAuthSuccessMessagePreparator(context, this);
    }

}
