/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.crypto;

import de.rub.nds.sshattacker.core.session.Session;
import de.rub.nds.sshattacker.core.session.cipher.SessionCipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Encryptor extends SessionCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    public Encryptor(SessionCipher cipher) {
        super(cipher);
    }

    public abstract void encrypt(Session object);
}
