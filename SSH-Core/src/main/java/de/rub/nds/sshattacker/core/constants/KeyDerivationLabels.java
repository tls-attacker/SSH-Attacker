/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public class KeyDerivationLabels {
    public static final char INITIAL_IV_CLIENT_TO_SERVER = 'A';
    public static final char INITIAL_IV_SERVER_TO_CLIENT = 'B';
    public static final char ENCRYPTION_KEY_CLIENT_TO_SERVER = 'C';
    public static final char ENCRYPTION_KEY_SERVER_TO_CLIENT = 'D';
    public static final char INTEGRITY_KEY_CLIENT_TO_SERVER = 'E';
    public static final char INTEGRITY_KEY_SERVER_TO_CLIENT = 'F';
}
