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
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchangeEncapsulation;
import de.rub.nds.sshattacker.core.crypto.kex.Sntrup761X25519KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.Sntrup761X25519KeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class Sntrup761X25519KeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<Sntrup761X25519KeyExchangeReplyMessage> {

    public Sntrup761X25519KeyExchangeReplyMessagePreparator(Chooser chooser, Sntrup761X25519KeyExchangeReplyMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEX_SNTRUP761_X25519_REPLY);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext(), getObject());
        prepareMultiPrecisionInteger();
        chooser.getSntrup761X25591KeyExchange().combineSharedSecrets();
        chooser.getContext().setSharedSecret(chooser.getSntrup761X25591KeyExchange().getSharedSecret());
        chooser.getContext().getExchangeHashInputHolder().setSharedSecret(chooser.getSntrup761X25591KeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(chooser.getContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext());

    }

    private void prepareMultiPrecisionInteger() {
        Sntrup761X25519KeyExchange keyExchange = chooser.getSntrup761X25591KeyExchange();
        HybridKeyExchangeAgreement ec25519 = keyExchange.getKeyAgreement("ec25519");
        HybridKeyExchangeEncapsulation sntrup761 = keyExchange.getKeyEncapsulation("sntrup761");
        ec25519.generateLocalKeyPair();
        sntrup761.encryptSharedSecret();

        getObject().setMultiPrecisionInteger(ArrayConverter.concatenate(sntrup761.getEncapsulatedSecret(),
                ec25519.getLocalKeyPair().getPublic().getEncoded()), true);

        chooser.getContext().getExchangeHashInputHolder()
                .setSntrupX25519ServerPublicKey((ArrayConverter.concatenate(sntrup761.getEncapsulatedSecret(),
                        ec25519.getLocalKeyPair().getPublic().getEncoded())));

    }
}
