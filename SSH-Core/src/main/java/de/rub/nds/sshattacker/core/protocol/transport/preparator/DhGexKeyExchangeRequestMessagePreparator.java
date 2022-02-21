/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessagePreparator(
            Chooser chooser, DhGexKeyExchangeRequestMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST);
        chooser.getContext().setKeyExchangeInstance(chooser.getDHGexKeyExchange());
        DhGexExchangeHash dhGexExchangeHash =
                DhGexExchangeHash.from(chooser.getContext().getExchangeHashInstance());
        dhGexExchangeHash.setMinimalGroupSize(chooser.getMinimalDHGroupSize());
        dhGexExchangeHash.setPreferredGroupSize(chooser.getPreferredDHGroupSize());
        dhGexExchangeHash.setMaximalGroupSize(chooser.getMaximalDHGroupSize());
        chooser.getContext().setExchangeHashInstance(dhGexExchangeHash);

        getObject().setMinimalGroupSize(chooser.getMinimalDHGroupSize());
        getObject().setPreferredGroupSize(chooser.getPreferredDHGroupSize());
        getObject().setMaximalGroupSize(chooser.getMaximalDHGroupSize());
    }
}
