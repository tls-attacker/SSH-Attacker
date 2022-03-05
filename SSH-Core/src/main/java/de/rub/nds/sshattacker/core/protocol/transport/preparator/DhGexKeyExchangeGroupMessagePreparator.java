/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.NamedDHGroup;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeGroupMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeGroupMessage> {

    public DhGexKeyExchangeGroupMessagePreparator(
            Chooser chooser, DhGexKeyExchangeGroupMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_GROUP);

        // TODO: Pay respect to clients' request
        getObject().setGroupGenerator(NamedDHGroup.GROUP14.getGenerator(), true);
        getObject().setGroupModulus(NamedDHGroup.GROUP14.getModulus(), true);
    }
}
