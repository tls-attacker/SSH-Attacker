/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class RsaKeyExchangeSecretMessagePreparator
        extends SshMessagePreparator<RsaKeyExchangeSecretMessage> {

    public RsaKeyExchangeSecretMessagePreparator(
            Chooser chooser, RsaKeyExchangeSecretMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXRSA_SECRET);
    }

    @Override
    public void prepareMessageSpecificContents() {
        KeyExchangeUtil.generateSharedSecret(chooser.getContext(), chooser.getRsaKeyExchange());
        prepareEncryptedSecret();
    }

    private void prepareEncryptedSecret() {
        byte[] encryptedSecret = chooser.getRsaKeyExchange().encryptSharedSecret();
        getObject().setEncryptedSecret(encryptedSecret, true);
        chooser.getContext().getExchangeHashInputHolder().setRsaEncryptedSecret(encryptedSecret);
    }
}
