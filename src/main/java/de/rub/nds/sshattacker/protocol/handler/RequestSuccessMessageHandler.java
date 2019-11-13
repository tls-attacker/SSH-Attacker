package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.state.SshContext;

public class RequestSuccessMessageHandler extends Handler<RequestSuccessMessageHandler> {

    public RequestSuccessMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(RequestSuccessMessageHandler msg) {
    }

}
