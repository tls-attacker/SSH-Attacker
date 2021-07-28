/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhNamedExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhKeyExchangeInitMessagePreparator extends Preparator<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessagePreparator(SshContext context, DhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        DhKeyExchange keyExchange = DhKeyExchange.newInstance(context.getKeyExchangeAlgorithm().orElseThrow(PreparationException::new));
        keyExchange.generateLocalKeyPair();
        context.setKeyExchangeInstance(keyExchange);
        DhNamedExchangeHash dhNamedExchangeHash = DhNamedExchangeHash.from(context.getExchangeHashInstance());
        dhNamedExchangeHash.setClientDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        context.setExchangeHashInstance(dhNamedExchangeHash);

        message.setMessageID(MessageIDConstant.SSH_MSG_KEXDH_INIT);
        message.setPublicKey(keyExchange.getLocalKeyPair().getPublic().getY(), true);
    }
}
