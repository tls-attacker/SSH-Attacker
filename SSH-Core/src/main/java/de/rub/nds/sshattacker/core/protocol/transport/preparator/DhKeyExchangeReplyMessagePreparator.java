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

    public DhKeyExchangeReplyMessagePreparator(Chooser chooser, DhKeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXDH_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        DhKeyExchangeReplyMessage message = getObject();
        SshContext context = chooser.getContext();
        KeyExchangeUtil.prepareHostKeyMessage(context, message);
        prepareEphemeralPublicKey();
        KeyExchangeUtil.computeSharedSecret(context, chooser.getDhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void prepareEphemeralPublicKey() {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        keyExchange.generateLocalKeyPair();
        BigInteger pubKey = keyExchange.getLocalKeyPair().getPublicKey().getY();

        getObject().setSoftlyEphemeralPublicKey(pubKey, true, chooser.getConfig());

        chooser.getContext().getExchangeHashInputHolder().setDhServerPublicKey(pubKey);
    }
}
