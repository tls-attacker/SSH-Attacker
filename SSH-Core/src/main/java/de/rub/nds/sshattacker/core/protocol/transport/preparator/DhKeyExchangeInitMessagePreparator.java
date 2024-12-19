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
import java.math.BigInteger;

public class DhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessagePreparator(Chooser chooser, DhKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXDH_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        keyExchange.generateLocalKeyPair();
        BigInteger pubKey = keyExchange.getLocalKeyPair().getPublicKey().getY();

        object.setSoftlyEphemeralPublicKey(pubKey, true, config);

        chooser.getContext().getExchangeHashInputHolder().setDhClientPublicKey(pubKey);
    }
}
