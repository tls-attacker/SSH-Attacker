/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessagePreparator(Chooser chooser, DhKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXDH_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        keyExchange.generateKeyPair();
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setDhClientPublicKey(keyExchange.getLocalKeyPair().getPublicKey().getY());

        getObject()
                .setEphemeralPublicKey(keyExchange.getLocalKeyPair().getPublicKey().getY(), true);
    }
}
