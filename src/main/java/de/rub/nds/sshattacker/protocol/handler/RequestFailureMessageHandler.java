package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.RequestFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class RequestFailureMessageHandler extends Handler<RequestFailureMessage> {

    public RequestFailureMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(RequestFailureMessage msg) {
    }

}
