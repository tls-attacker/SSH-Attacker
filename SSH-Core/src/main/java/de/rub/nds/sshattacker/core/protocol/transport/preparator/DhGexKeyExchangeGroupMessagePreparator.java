/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.NamedDHGroup;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeGroupMessagePreparator
        extends Preparator<DhGexKeyExchangeGroupMessage> {

    public DhGexKeyExchangeGroupMessagePreparator(
            SshContext context, DhGexKeyExchangeGroupMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_GROUP);

        // TODO: Pay respect to clients' request
        message.setGroupGenerator(NamedDHGroup.GROUP14.getGenerator(), true);
        message.setGroupModulus(NamedDHGroup.GROUP14.getModulus(), true);
    }
}
