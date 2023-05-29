/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.crypto;

import de.rub.nds.sshattacker.core.session.cipher.SessionCipher;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SessionCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ArrayList<SessionCipher> sessionCipherList;

    public SessionCryptoUnit(SessionCipher sessionCipher) {
        this.sessionCipherList = new ArrayList<>();
        sessionCipherList.add(0, sessionCipher);
    }

    public SessionCipher getSessionMostRecentCipher() {
        return sessionCipherList.get(sessionCipherList.size() - 1);
    }

    public SessionCipher getSessionCipher(int epoch) {
        if (sessionCipherList.size() > epoch) {
            return sessionCipherList.get(epoch);
        } else {
            LOGGER.warn("Got no RecordCipher for epoch: " + epoch + " using epoch 0 cipher");
            return sessionCipherList.get(0);
        }
    }

    public void addNewRecordCipher(SessionCipher sessionCipher) {
        this.sessionCipherList.add(sessionCipher);
    }

    public void removeAllCiphers() {
        this.sessionCipherList = new ArrayList<>();
    }

    public void removeCiphers(int toRemove) {
        while (toRemove > 0 && !sessionCipherList.isEmpty()) {
            sessionCipherList.remove(sessionCipherList.size() - 1);
            toRemove--;
        }
        if (toRemove > 0) {
            LOGGER.warn("Could not remove as many ciphers as specified");
        }
    }
}
