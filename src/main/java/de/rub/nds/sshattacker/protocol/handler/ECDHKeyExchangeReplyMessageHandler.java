package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ECDHKeyExchangeReplyMessageHandler extends Handler<ECDHKeyExchangeReplyMessage> {

    public ECDHKeyExchangeReplyMessageHandler(SshContext context, ECDHKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void handle() {
        context.setDefaultHostKeyType(message.getHostKeyType().getValue());
        context.setDefaultRsaExponent(message.getHostKeyRsaExponent().getValue());
        context.setDefaultRsaModulus(message.getHostKeyRsaModulus().getValue());
        context.setDefaultServerEcdhPublicKey(message.getEphemeralPublicKey().getValue());
        context.setKeyExchangeSignature(message.getSignature().getValue());
    }
}