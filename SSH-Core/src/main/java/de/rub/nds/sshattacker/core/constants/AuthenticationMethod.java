/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum AuthenticationMethod {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-10
     */
    PUBLICKEY("publickey"),
    PASSWORD("password"),
    HOST_BASED("hostbased"),
    NONE("none"),
    KEYBOARD_INTERACTIVE("keyboard-interactive"),
    GSSAPI_WITH_MIC("gssapi-with-mic"),
    GSSAPI_KEYEX("gssapi-keyex"),
    GSSAPI("gssapi"),
    EXTERNAL_KEYX("external-keyx");

    private final String name;

    AuthenticationMethod(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
