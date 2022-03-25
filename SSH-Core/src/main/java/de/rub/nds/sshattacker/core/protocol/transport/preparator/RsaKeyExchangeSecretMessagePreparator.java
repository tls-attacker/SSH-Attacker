/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessagePreparator(
            Chooser chooser, RsaKeyExchangeSecretMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXRSA_SECRET);
        prepareSharedSecret();
        updateExchangeHashWithSecrets();
    }

    private void prepareSharedSecret() {
        RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
        keyExchange.computeSharedSecret();
        chooser.getContext().setSharedSecret(keyExchange.getSharedSecret());
        LOGGER.debug("Shared secret: " + keyExchange.getSharedSecret());
        getObject().setEncryptedSecret(keyExchange.encryptSharedSecret(), true);
    }

    private void updateExchangeHashWithSecrets() {
        RsaKeyExchange keyExchange = chooser.getRsaKeyExchange();
        ExchangeHashInputHolder inputHolder = chooser.getContext().getExchangeHashInputHolder();
        inputHolder.setRsaEncryptedSecret(getObject().getEncryptedSecret().getValue());
        if (keyExchange.isComplete()) {
            inputHolder.setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to set shared secret in exchange hash, key exchange is still ongoing");
        }
    }
}
