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
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeInitMessagePreparator extends Preparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        EcdhKeyExchange ecdhKeyExchange = EcdhKeyExchange.newInstance(context.getKeyExchangeAlgorithm().orElseThrow(PreparationException::new));
        ecdhKeyExchange.generateLocalKeyPair();
        context.setKeyExchangeInstance(ecdhKeyExchange);
        EcdhExchangeHash ecdhExchangeHash = EcdhExchangeHash.from(context.getExchangeHashInstance());
        ecdhExchangeHash.setClientECDHPublicKey(ecdhKeyExchange.getLocalKeyPair().getPublic());
        context.setExchangeHashInstance(ecdhExchangeHash);

        byte[] encodedPublicKey = ecdhKeyExchange.getLocalKeyPair().getPublic().getEncoded();
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT.id);
        message.setPublicKey(encodedPublicKey);
        message.setPublicKeyLength(encodedPublicKey.length);
    }
}
