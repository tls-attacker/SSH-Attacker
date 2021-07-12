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
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeInitMessagePreparator extends Preparator<DhGexKeyExchangeInitMessage> {

    public DhGexKeyExchangeInitMessagePreparator(SshContext context, DhGexKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        DhKeyExchange keyExchange = (DhKeyExchange) context.getKeyExchangeInstance().orElseThrow(PreparationException::new);
        keyExchange.generateLocalKeyPair();
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if(exchangeHash instanceof DhGexExchangeHash) {
            ((DhGexExchangeHash) exchangeHash).setClientDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        } else {
            ((DhGexOldExchangeHash) exchangeHash).setClientDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        }

        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_INIT.id);
        message.setPublicKeyLength(keyExchange.getLocalKeyPair().getPublic().getEncoded().length);
        message.setPublicKey(keyExchange.getLocalKeyPair().getPublic().getY());
    }
}
