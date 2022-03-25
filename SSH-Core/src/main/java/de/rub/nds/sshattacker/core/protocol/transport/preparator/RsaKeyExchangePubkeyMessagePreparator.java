/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessagePreparator(
            Chooser chooser, RsaKeyExchangePubkeyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_PUBKEY);
        prepareHostKey();
        prepareTransientPublicKey();
        updateExchangeHashWithTransientPublicKey();
    }

    private void prepareHostKey() {
        SshPublicKey<?, ?> serverHostKey = chooser.getNegotiatedServerHostKey();
        chooser.getContext().setServerHostKey(serverHostKey);
        chooser.getContext().getExchangeHashInputHolder().setServerHostKey(serverHostKey);
        getObject().setHostKeyBytes(PublicKeyHelper.encode(serverHostKey), true);
    }

    private void prepareTransientPublicKey() {
        try {
            RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
            keyExchange.generateTransientKey();
            getObject()
                    .setTransientPublicKeyBytes(
                            PublicKeyHelper.encode(keyExchange.getTransientKey()), true);
        } catch (CryptoException e) {
            // This branch should never be reached as this would indicate an RSA key generation
            // failure
            LOGGER.warn(
                    "Transient public key preparation failed - workflow will continue but transient public key will be left empty");
            LOGGER.debug(e);
            getObject().setTransientPublicKeyBytes(new byte[0], true);
        }
    }

    private void updateExchangeHashWithTransientPublicKey() {
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setRsaTransientKey(getObject().getTransientPublicKey());
    }
}
