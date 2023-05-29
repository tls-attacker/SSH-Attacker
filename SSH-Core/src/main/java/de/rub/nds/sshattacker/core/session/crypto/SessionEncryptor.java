/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.crypto;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.session.Session;
import de.rub.nds.sshattacker.core.session.cipher.SessionCipher;
import de.rub.nds.sshattacker.core.session.cipher.SessionCipherFactory;
import de.rub.nds.sshattacker.core.session.cipher.SessionNullCipher;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext sshContext;

    private final SessionNullCipher nullCipher;

    public SessionEncryptor(SessionCipher sessionCipher, SshContext sshContext) {
        super(sessionCipher);
        this.sshContext = sshContext;
        nullCipher = SessionCipherFactory.getNullCipher(sshContext);
    }

    @Override
    public void encrypt(Session session) {
        LOGGER.debug("Encrypting Record:");
        SessionCipher sessionCipher;
        sessionCipher = getSessionMostRecentCipher();
        /*if (sshContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            sessionCipher = getSessionCipher(session.getEpoch().getValue());
        } else {
            sessionCipher = getSessionMostRecentCipher();
        }*/
        try {
            session.setSequenceNumber(
                    BigInteger.valueOf(sessionCipher.getState().getWriteSequenceNumber()));
            sessionCipher.encrypt(session);
        } catch (CryptoException ex) {
            LOGGER.warn("Could not encrypt BlobRecord. Using NullCipher", ex);
            try {
                nullCipher.encrypt(session);
            } catch (CryptoException ex1) {
                LOGGER.error("Could not encrypt with NullCipher", ex1);
            }
        }
        sessionCipher.getState().increaseWriteSequenceNumber();
        /*if (sshContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            session.getComputations().setUsedTls13KeySetType(sshContext.getActiveKeySetTypeWrite());
        }*/
    }
}
