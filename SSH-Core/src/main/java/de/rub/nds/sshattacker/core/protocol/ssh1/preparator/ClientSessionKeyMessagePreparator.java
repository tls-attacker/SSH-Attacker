/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public class ClientSessionKeyMessagePreparator extends SshMessagePreparator<ClientSessionKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    public ClientSessionKeyMessagePreparator(
            Chooser chooser, ClientSessionKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_PUBLIC_KEY);
        this.combiner = combiner;
    }

    private void prepareAntiSpoofingCookie(){
        getObject().setAntiSpoofingCookie(chooser.getConfig().getAntiSpoofingCookie());
    }

    private void prepareSessionID(){
        chooser.getContext().getSshContext().getServerKey();
        chooser.getContext().getSshContext().getHostKey();
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");

    }


}
