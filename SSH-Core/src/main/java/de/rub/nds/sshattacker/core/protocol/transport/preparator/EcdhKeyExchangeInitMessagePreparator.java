/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.AbstractEcdhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class EcdhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(
            Chooser chooser, EcdhKeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_ECDH_INIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        AbstractEcdhKeyExchange keyExchange = chooser.getEcdhKeyExchange();

        Config sshConfig = chooser.getConfig();

        keyExchange.generateLocalKeyPair();
        byte[] encodedPublicKey = keyExchange.getLocalKeyPair().getPublic().getEncoded();

        // Set custom public key in exchange hash and message if we are using the invalid curve
        // attack
        if (sshConfig.getIsInvalidCurveAttack()) {
            byte[] customPubKey = new byte[65];

            customPubKey = sshConfig.getCustomEcPublicKey();

            chooser.getContext().getExchangeHashInputHolder().setEcdhClientPublicKey(customPubKey);
            getObject().setEphemeralPublicKey(customPubKey, true);
        } else {
            chooser.getContext()
                    .getExchangeHashInputHolder()
                    .setEcdhClientPublicKey(encodedPublicKey);
            getObject().setEphemeralPublicKey(encodedPublicKey, true);
        }
    }
}
