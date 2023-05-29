/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.crypto;

import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.session.Session;
import de.rub.nds.sshattacker.core.session.cipher.SessionCipher;
import de.rub.nds.sshattacker.core.session.cipher.SessionCipherFactory;
import de.rub.nds.sshattacker.core.session.cipher.SessionNullCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext sshContext;

    private SessionNullCipher nullCipher;

    public SessionDecryptor(SessionCipher sessionCipher, SshContext sshContext) {
        super(sessionCipher);
        this.sshContext = sshContext;
        nullCipher = SessionCipherFactory.getNullCipher(sshContext);
    }

    @Override
    public void decrypt(Session session) throws ParserException {
        LOGGER.debug("Decrypting Record");
        SessionCipher sessionCipher;
        /*if (sshContext.getChooser().getSelectedProtocolVersion().isDTLS()
                && session.getEpoch() != null
                && session.getEpoch().getValue() != null) {
            sessionCipher = getSessionCipher(session.getEpoch().getValue());
        } else {
            sessionCipher = getSessionMostRecentCipher();
        }*/
        session.prepareComputations();
        /*ProtocolVersion version =
                ProtocolVersion.getProtocolVersion(session.getProtocolVersion().getValue());
        if (version == null || !version.isDTLS()) {
            session.setSequenceNumber(
                    BigInteger.valueOf(sessionCipher.getState().getReadSequenceNumber()));
        }

        try {
            if (!sshContext.getChooser().getSelectedProtocolVersion().isTLS13()
                    || session.getContentMessageType() != ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                sessionCipher.decrypt(session);
                sessionCipher.getState().increaseReadSequenceNumber();
            } else {
                LOGGER.debug("Skipping decryption for legacy CCS");
                new RecordNullCipher(sshContext, sessionCipher.getState()).decrypt(session);
            }
        } catch (CryptoException ex) {
            throw new ParserException(ex);
        }*/
    }
}
