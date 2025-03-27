/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum OpenSshTunnelMode {
    /*
     * Sources:
     *  - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    /** Layer 3 packets */
    SSH_TUNMODE_POINTTOPOINT(1),
    /** Layer 2 frames */
    SSH_TUNMODE_ETHERNET(2);

    private final int value;

    OpenSshTunnelMode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
