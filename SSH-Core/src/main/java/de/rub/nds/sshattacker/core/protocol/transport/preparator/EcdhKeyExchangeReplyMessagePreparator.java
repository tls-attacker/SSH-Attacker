/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class EcdhKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessagePreparator(
            Chooser chooser, EcdhKeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_ECDH_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        SshContext context = chooser.getContext();
        KeyExchangeUtil.prepareHostKeyMessage(context, object);
        prepareEphemeralPublicKey();
        KeyExchangeUtil.computeSharedSecret(context, chooser.getEcdhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void prepareEphemeralPublicKey() {
        AbstractEcdhKeyExchange keyExchange = chooser.getEcdhKeyExchange();
        keyExchange.generateLocalKeyPair();
        byte[] pubKey = keyExchange.getLocalKeyPair().getPublicKey().getEncoded();

        object.setSoftlyEphemeralPublicKey(pubKey, true, config);

        chooser.getContext().getExchangeHashInputHolder().setEcdhServerPublicKey(pubKey);
    }
}
