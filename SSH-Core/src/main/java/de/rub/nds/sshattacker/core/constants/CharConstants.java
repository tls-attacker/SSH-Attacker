/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public final class CharConstants {
    public static final byte CARRIAGE_RETURN = 0x0d;
    public static final byte NEWLINE = 0x0a;
    public static final char VERSION_COMMENT_SEPARATOR = ' ';
    public static final char ALGORITHM_SEPARATOR = ',';

    private CharConstants() {
        super();
    }
}
