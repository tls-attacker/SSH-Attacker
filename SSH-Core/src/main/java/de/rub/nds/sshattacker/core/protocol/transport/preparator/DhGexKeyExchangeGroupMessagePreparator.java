/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
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
        getObject().setMessageId(MessageIdConstant.SSH_MSG_KEX_DH_GEX_GROUP);
        selectGroupParameters();
        updateExchangeHashWithGroupParameters();
        prepareGroupParameters();
    }

    private void selectGroupParameters() {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        if (chooser.getContext().isOldGroupRequestReceived()) {
            keyExchange.selectGroup(chooser.getPreferredDhGroupSize());
        } else {
            keyExchange.selectGroup(
                    chooser.getMinimalDhGroupSize(),
                    chooser.getPreferredDhGroupSize(),
                    chooser.getMaximalDhGroupSize());
        }
    }

    private void updateExchangeHashWithGroupParameters() {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        inputHolder.setDhGexGroupGenerator(keyExchange.getGenerator());
        inputHolder.setDhGexGroupModulus(keyExchange.getModulus());
    }

    private void prepareGroupParameters() {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        getObject().setGroupGenerator(keyExchange.getGenerator(), true);
        getObject().setGroupModulus(keyExchange.getModulus(), true);
    }
}
