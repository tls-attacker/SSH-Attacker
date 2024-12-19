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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class DhGexKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeInitMessage> {

    public DhGexKeyExchangeInitMessagePreparator(
            Chooser chooser, DhGexKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_DH_GEX_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        keyExchange.generateLocalKeyPair();
        BigInteger pubKey = keyExchange.getLocalKeyPair().getPublicKey().getY();

        object.setSoftlyEphemeralPublicKey(pubKey, true, config);

        chooser.getContext().getExchangeHashInputHolder().setDhGexClientPublicKey(pubKey);
    }
}
