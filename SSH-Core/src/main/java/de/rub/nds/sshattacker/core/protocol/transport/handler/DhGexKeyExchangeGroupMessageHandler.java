/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;

public class DhGexKeyExchangeGroupMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeGroupMessage> {

    public DhGexKeyExchangeGroupMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(DhGexKeyExchangeGroupMessage message) {
        setGroupParametersFromMessage(message);
        updateExchangeHashWithGroupParameters(message);
    }

    private void setGroupParametersFromMessage(DhGexKeyExchangeGroupMessage msg) {
        DhKeyExchange keyExchange = sshContext.getChooser().getDhGexKeyExchange();
        keyExchange.setModulus(msg.getGroupModulus().getValue());
        keyExchange.setGenerator(msg.getGroupGenerator().getValue());
    }

    private void updateExchangeHashWithGroupParameters(DhGexKeyExchangeGroupMessage msg) {
        ExchangeHashInputHolder inputHolder = sshContext.getExchangeHashInputHolder();
        inputHolder.setDhGexGroupModulus(msg.getGroupModulus().getValue());
        inputHolder.setDhGexGroupGenerator(msg.getGroupGenerator().getValue());
    }
}
