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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessagePreparator
        extends Preparator<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessagePreparator(
            SshContext context, DhGexKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REPLY);

        message.setHostKey(new byte[0], true);
        message.setEphemeralPublicKey(BigInteger.ZERO, true);
        // TODO: Implement signature calculation
        message.setSignature(new byte[0], true);
    }
}
