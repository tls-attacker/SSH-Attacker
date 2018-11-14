package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ECDHKeyExchangeInitMessagePreparator extends Preparator<ECDHKeyExchangeInitMessage> {

    public ECDHKeyExchangeInitMessagePreparator(SshContext context, ECDHKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setPublicKey(context.getDefaultClientEcdhPublicKey());
        message.setPublicKeyLength(message.getPublicKey().getValue().length);
    }

}
