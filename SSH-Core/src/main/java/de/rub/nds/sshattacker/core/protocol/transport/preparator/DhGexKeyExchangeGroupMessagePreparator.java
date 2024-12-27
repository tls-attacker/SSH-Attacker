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
import java.math.BigInteger;

public class DhGexKeyExchangeGroupMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeGroupMessage> {

    public DhGexKeyExchangeGroupMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEX_DH_GEX_GROUP);
    }

    @Override
    public void prepareMessageSpecificContents(
            DhGexKeyExchangeGroupMessage object, Chooser chooser) {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        if (chooser.getContext().isOldGroupRequestReceived()) {
            keyExchange.selectGroup(chooser.getPreferredDhGroupSize());
        } else {
            keyExchange.selectGroup(
                    chooser.getMinimalDhGroupSize(),
                    chooser.getPreferredDhGroupSize(),
                    chooser.getMaximalDhGroupSize());
        }
        BigInteger generator = keyExchange.getGenerator();
        BigInteger modulus = keyExchange.getModulus();

        object.setSoftlyGroupGenerator(generator, true, chooser.getConfig());
        object.setSoftlyGroupModulus(modulus, true, chooser.getConfig());

        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        inputHolder.setDhGexGroupGenerator(generator);
        inputHolder.setDhGexGroupModulus(modulus);
    }
}
