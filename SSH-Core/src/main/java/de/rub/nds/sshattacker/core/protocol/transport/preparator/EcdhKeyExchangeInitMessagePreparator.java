/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.AbstractEcdhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class EcdhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEX_ECDH_INIT);
    }

    @Override
    public void prepareMessageSpecificContents(EcdhKeyExchangeInitMessage object, Chooser chooser) {
        AbstractEcdhKeyExchange<?, ?> keyExchange = chooser.getEcdhKeyExchange();
        keyExchange.generateKeyPair();
        byte[] pubKey = keyExchange.getLocalKeyPair().getPublicKey().getEncoded();

        object.setSoftlyEphemeralPublicKey(pubKey, true, chooser.getConfig());

        chooser.getContext().getExchangeHashInputHolder().setEcdhClientPublicKey(pubKey);
    }
}
