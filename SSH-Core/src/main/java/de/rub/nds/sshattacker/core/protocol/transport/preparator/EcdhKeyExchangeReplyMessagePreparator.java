/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeReplyMessagePreparator extends Preparator<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessagePreparator(
            SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY);

        getObject().setHostKey(new byte[0], true);
        getObject().setEphemeralPublicKey(new byte[0], true);
        // TODO implement signature calculation
        getObject().setSignature(new byte[0], true);
    }
}
