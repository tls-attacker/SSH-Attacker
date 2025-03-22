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
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeRequestMessage> {

    public DhGexKeyExchangeRequestMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEX_DH_GEX_REQUEST);
    }

    @Override
    protected void prepareMessageSpecificContents(
            DhGexKeyExchangeRequestMessage object, Chooser chooser) {
        Integer minimalDhGroupSize = chooser.getMinimalDhGroupSize();
        Integer preferredDhGroupSize = chooser.getPreferredDhGroupSize();
        Integer maximalDhGroupSize = chooser.getMaximalDhGroupSize();

        object.setMinimalGroupSize(minimalDhGroupSize);
        object.setPreferredGroupSize(preferredDhGroupSize);
        object.setMaximalGroupSize(maximalDhGroupSize);

        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        inputHolder.setDhGexMinimalGroupSize(minimalDhGroupSize);
        inputHolder.setDhGexPreferredGroupSize(preferredDhGroupSize);
        inputHolder.setDhGexMaximalGroupSize(maximalDhGroupSize);
    }
}
