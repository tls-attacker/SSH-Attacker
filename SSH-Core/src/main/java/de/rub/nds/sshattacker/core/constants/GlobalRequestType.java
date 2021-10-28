/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum GlobalRequestType {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-12
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    // [ RFC 4254 ]
    TCPIP_FORWARD("tcpip-forward"),
    CANCEL_TCPIP_FORWARD("cancel-tcpip-forward"),
    // Vendor extensions
    // [ OpenSSH ]
    NO_MORE_SESSIONS_OPENSSH_COM("no-more-sessions@openssh.com"),
    STREAMLOCAL_FORWARD_OPENSSH_COM("streamlocal-forward@openssh.com"),
    CANCEL_STREAMLOCAL_FORWARD_OPENSSH_COM("cancel-streamlocal-forward@openssh.com"),
    HOSTKEYS_00_OPENSSH_COM("hostkeys-00@openssh.com"),
    HOSTKEYS_PROVE_00_OPENSSH_COM("hostkeys-prove-00@openssh.com");

    private final String name;

    GlobalRequestType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
