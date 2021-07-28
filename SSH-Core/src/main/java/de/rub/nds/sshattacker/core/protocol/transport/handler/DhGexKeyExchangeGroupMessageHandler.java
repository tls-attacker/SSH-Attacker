/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeGroupMessageHandler extends Handler<DhGexKeyExchangeGroupMessage> {

    public DhGexKeyExchangeGroupMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhGexKeyExchangeGroupMessage msg) {
        DhKeyExchange dhKeyExchange = (DhKeyExchange) context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        dhKeyExchange.setModulus(msg.getGroupModulus().getValue());
        dhKeyExchange.setGenerator(msg.getGroupGenerator().getValue());

        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if(exchangeHash instanceof DhGexExchangeHash) {
            DhGexExchangeHash dhGexExchangeHash = (DhGexExchangeHash) exchangeHash;
            dhGexExchangeHash.setGroupModulus(msg.getGroupModulus().getValue());
            dhGexExchangeHash.setGroupGenerator(msg.getGroupGenerator().getValue());
        } else {
            DhGexOldExchangeHash dhGexOldExchangeHash = (DhGexOldExchangeHash) exchangeHash;
            dhGexOldExchangeHash.setGroupModulus(msg.getGroupModulus().getValue());
            dhGexOldExchangeHash.setGroupGenerator(msg.getGroupGenerator().getValue());
        }
    }
}
