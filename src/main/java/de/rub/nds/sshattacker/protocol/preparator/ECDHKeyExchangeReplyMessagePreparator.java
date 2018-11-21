package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ECDHKeyExchangeReplyMessagePreparator extends Preparator<ECDHKeyExchangeReplyMessage> {

    public ECDHKeyExchangeReplyMessagePreparator(SshContext context, ECDHKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setHostKeyLength(context.getDefaultRsaExponent().bitLength());
        message.setHostKeyType(context.getDefaultHostKeyType());
        message.setHostKeyTypeLength(context.getDefaultHostKeyType().length());
        message.setExponentLength(context.getDefaultRsaExponent().bitLength());
        message.setExponent(context.getDefaultRsaExponent());
        message.setModulus(context.getDefaultRsaModulus());
        message.setModulusLength(context.getDefaultRsaModulus().bitLength());
        message.setEphemeralPublicKey(context.getDefaultServerEcdhPublicKey());
        message.setEphemeralPublicKeyLength(context.getDefaultServerEcdhPublicKey().length);
        // TODO implement signature calculation
        //message.setSignature();
        //message.setSignatureLength(0);
    }

}
