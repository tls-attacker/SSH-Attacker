/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class Sntrup761X25519KeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<HybridKeyExchangeReplyMessage> {

    public Sntrup761X25519KeyExchangeReplyMessagePreparator(
            Chooser chooser, HybridKeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_HBR_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), getObject());
        prepareHybridKey();
        chooser.getHybridKeyExchange().combineSharedSecrets();
        chooser.getContext()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(chooser.getContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext());
    }

    private void prepareHybridKey() {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement ec25519 = keyExchange.getKeyAgreement();
        KeyEncapsulation sntrup761 = keyExchange.getKeyEncapsulation();
        ec25519.generateLocalKeyPair();
        sntrup761.encryptSharedSecret();

        getObject()
                .setHybridKey(
                        ArrayConverter.concatenate(
                                sntrup761.getEncapsulatedSecret(),
                                ec25519.getLocalKeyPair().getPublic().getEncoded()),
                        true);

        chooser.getContext()
                .getExchangeHashInputHolder()
                .setHybridServerPublicKey(
                        (ArrayConverter.concatenate(
                                sntrup761.getEncapsulatedSecret(),
                                ec25519.getLocalKeyPair().getPublic().getEncoded())));
    }
}
