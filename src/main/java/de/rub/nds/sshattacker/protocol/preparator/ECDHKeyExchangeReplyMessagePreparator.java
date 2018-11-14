package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ECDHKeyExchangeReplyMessagePreparator extends Preparator<ECDHKeyExchangeReplyMessage> {

    public ECDHKeyExchangeReplyMessagePreparator(SshContext context, ECDHKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.set
    }

}
