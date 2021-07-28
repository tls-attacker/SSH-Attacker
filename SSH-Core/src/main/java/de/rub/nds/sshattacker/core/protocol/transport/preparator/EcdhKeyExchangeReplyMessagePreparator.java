/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;

public class EcdhKeyExchangeReplyMessagePreparator extends Preparator<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessagePreparator(SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY);

        message.setHostKey(new byte[0], true);
        message.setEphemeralPublicKey(new byte[0], true);
        // TODO implement signature calculation
        message.setSignature(new byte[0], true);
    }

}
