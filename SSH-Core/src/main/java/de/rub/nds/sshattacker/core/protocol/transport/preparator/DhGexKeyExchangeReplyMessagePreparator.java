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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeReplyMessage> {

    public DhGexKeyExchangeReplyMessagePreparator(
            Chooser chooser, DhGexKeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_DH_GEX_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext().getSshContext(), getObject());
        prepareEphemeralPublicKey();
        KeyExchangeUtil.computeSharedSecret(
                chooser.getContext().getSshContext(), chooser.getDhGexKeyExchange());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext().getSshContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(
                chooser.getContext().getSshContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext().getSshContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext().getSshContext());
    }

    private void prepareEphemeralPublicKey() {
        DhKeyExchange keyExchange = chooser.getDhGexKeyExchange();
        keyExchange.generateLocalKeyPair();
        getObject().setEphemeralPublicKey(keyExchange.getLocalKeyPair().getPublic().getY(), true);
        // Update exchange hash with local public key
        chooser.getContext()
                .getSshContext()
                .getExchangeHashInputHolder()
                .setDhGexServerPublicKey(keyExchange.getLocalKeyPair().getPublic().getY());
    }

    private void prepareSignature() {}
}
