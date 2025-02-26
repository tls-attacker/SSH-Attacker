/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {
    private static Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEXRSA_SECRET);
    }

    @Override
    public void prepareMessageSpecificContents(
            RsaKeyExchangeSecretMessage object, Chooser chooser) {
        byte[] encryptedSecret;
        try {
            chooser.getRsaKeyExchange().encapsulate();
            encryptedSecret = chooser.getRsaKeyExchange().getEncapsulation();
        } catch (CryptoException e) {
            LOGGER.warn(
                    "Error while preparing RsaKeyExchangeSecretMessage - encapsulation failed", e);
            encryptedSecret = new byte[0];
        }

        object.setEncryptedSecret(encryptedSecret, true);

        chooser.getContext().getExchangeHashInputHolder().setRsaEncryptedSecret(encryptedSecret);
    }
}
