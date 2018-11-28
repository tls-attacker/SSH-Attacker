package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ECDHKeyExchangeReplyMessageHandler extends Handler<ECDHKeyExchangeReplyMessage> {

    public ECDHKeyExchangeReplyMessageHandler(SshContext context, ECDHKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void handle() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
