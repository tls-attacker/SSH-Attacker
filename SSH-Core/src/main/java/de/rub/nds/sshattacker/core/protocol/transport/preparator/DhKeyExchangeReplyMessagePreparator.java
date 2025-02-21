/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class DhKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<DhKeyExchangeReplyMessage> {

    public DhKeyExchangeReplyMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEXDH_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents(DhKeyExchangeReplyMessage object, Chooser chooser) {
        SshContext context = chooser.getContext();
        KeyExchangeUtil.prepareHostKeyMessage(context, object);
        prepareEphemeralPublicKey(object, chooser);
        KeyExchangeUtil.computeSharedSecret(context, chooser.getDhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private static void prepareEphemeralPublicKey(
            DhKeyExchangeReplyMessage object, Chooser chooser) {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        keyExchange.generateKeyPair();
        BigInteger pubKey = keyExchange.getLocalKeyPair().getPublicKey().getY();

        object.setSoftlyEphemeralPublicKey(pubKey, true, chooser.getConfig());

        chooser.getContext().getExchangeHashInputHolder().setDhServerPublicKey(pubKey);
    }
}
