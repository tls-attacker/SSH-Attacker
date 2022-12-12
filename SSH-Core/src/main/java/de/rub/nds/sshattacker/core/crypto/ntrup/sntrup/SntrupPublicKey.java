/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

public class SntrupPublicKey {
    private byte[] pubK;

    public SntrupPublicKey(byte[] pubK) {
        this.pubK = pubK;
    }

    public byte[] getPubK() {
        return pubK;
    }

    public void setPubK(byte[] pubK) {
        this.pubK = pubK;
    }
}
