package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.handler.RequestFailureMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.preparator.RequestFailureMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.RequestFailureMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestFailureMessage extends Message {

    @Override
    public Handler getHandler(SshContext context) {
        return new RequestFailureMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new RequestFailureMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new RequestFailureMessagePreparator(context, this);
    }

}
