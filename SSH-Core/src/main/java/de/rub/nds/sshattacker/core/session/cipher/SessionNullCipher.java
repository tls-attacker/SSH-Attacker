/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.cipher;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.session.Session;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionNullCipher extends SessionCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public SessionNullCipher(SshContext sshContext, CipherState state) {
        super(sshContext, state);
    }

    @Override
    public void encrypt(Session session) throws CryptoException {

        LOGGER.debug("Encrypting Record: (null cipher)");
        session.prepareComputations();
        byte[] cleanBytes = session.getCleanProtocolMessageBytes().getValue();
        session.setProtocolMessageBytes(cleanBytes);
    }

    @Override
    public void decrypt(Session session) throws CryptoException {
        LOGGER.debug("Decrypting Record: (null cipher)");
        session.prepareComputations();
        byte[] protocolMessageBytes = session.getProtocolMessageBytes().getValue();
        session.setCleanProtocolMessageBytes(protocolMessageBytes);
    }
}
