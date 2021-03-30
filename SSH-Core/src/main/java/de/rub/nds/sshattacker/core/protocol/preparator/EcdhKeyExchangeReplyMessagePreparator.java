/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;

public class EcdhKeyExchangeReplyMessagePreparator extends Preparator<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessagePreparator(SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY.id);

        message.setHostKeyLength(Integer.MAX_VALUE);
        message.setHostKeyType("");
        message.setHostKeyTypeLength(Integer.MAX_VALUE);
        message.setHostKeyEcc(new byte[0]);
        message.setHostKeyEccLength(Integer.MAX_VALUE);
        message.setExponentLength(Integer.MAX_VALUE);
        message.setExponent(BigInteger.ZERO);
        message.setModulus(BigInteger.ZERO);
        message.setModulusLength(Integer.MAX_VALUE);
        message.setEphemeralPublicKey(new byte[0]);
        message.setEphemeralPublicKeyLength(Integer.MAX_VALUE);
        message.setEccCurveIdentifier("");
        message.setEccCurveIdentifierLength(Integer.MAX_VALUE);
        // TODO implement signature calculation
        message.setSignature(new byte[0]);
        message.setSignatureLength(Integer.MAX_VALUE);
    }

}
