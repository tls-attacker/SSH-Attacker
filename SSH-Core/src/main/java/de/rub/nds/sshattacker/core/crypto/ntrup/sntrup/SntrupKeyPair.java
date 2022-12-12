/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

public class SntrupKeyPair {
    private SntrupPublicKey pubK;
    private SntrupPrivateKey privK;

    public SntrupKeyPair(SntrupPublicKey pubK, SntrupPrivateKey privK) {
        this.pubK = pubK;
        this.privK = privK;
    }

    public SntrupPublicKey getPubK() {
        return pubK;
    }

    public void setPubK(SntrupPublicKey pubK) {
        this.pubK = pubK;
    }

    public SntrupPrivateKey getPrivK() {
        return privK;
    }

    public void setPrivK(SntrupPrivateKey privK) {
        this.privK = privK;
    }
}
