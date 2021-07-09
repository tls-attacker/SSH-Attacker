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
import de.rub.nds.sshattacker.core.crypto.ECDHKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeInitMessagePreparator extends Preparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        ECDHKeyExchange ecdhKeyExchange = new ECDHKeyExchange(context.getKeyExchangeAlgorithm().orElseThrow(PreparationException::new));
        ecdhKeyExchange.generateKeyPair();
        context.setKeyExchangeInstance(ecdhKeyExchange);

        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT.id);
        message.setPublicKey(context.getChooser().getLocalEphemeralPublicKey());
        message.setPublicKeyLength(context.getChooser().getLocalEphemeralPublicKey().length);
    }
}
