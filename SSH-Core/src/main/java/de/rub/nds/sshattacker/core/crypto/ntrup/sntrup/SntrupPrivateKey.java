/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

public class SntrupPrivateKey {
    byte [] privK;
    public SntrupPrivateKey(byte[] privK) {
        this.privK = privK;
    }
    public byte[] getPrivK() {
        return privK;
    }
    public void setPrivK(byte[] privK) {
        this.privK = privK;
    }
}
