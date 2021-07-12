/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeOldRequestMessagePreparator extends Preparator<DhGexKeyExchangeOldRequestMessage> {

    public DhGexKeyExchangeOldRequestMessagePreparator(SshContext context, DhGexKeyExchangeOldRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        DhKeyExchange keyExchange = DhKeyExchange.newInstance(context.getKeyExchangeAlgorithm().orElseThrow(PreparationException::new));
        context.setKeyExchangeInstance(keyExchange);
        DhGexOldExchangeHash dhGexOldExchangeHash = DhGexOldExchangeHash.from(context.getExchangeHashInstance());
        dhGexOldExchangeHash.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        context.setExchangeHashInstance(dhGexOldExchangeHash);

        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD.id);
        message.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
    }
}
