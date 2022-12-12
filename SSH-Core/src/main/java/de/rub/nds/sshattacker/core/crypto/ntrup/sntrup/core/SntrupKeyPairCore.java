/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

public class SntrupKeyPairCore {

    SntrupPrivKeyCore privKey;
    SntrupPubKeyCore pubKey;

    public SntrupKeyPairCore(SntrupPrivKeyCore privKey, SntrupPubKeyCore pubKey) {
        this.privKey = privKey;
        this.pubKey = pubKey;
    }

    public SntrupPrivKeyCore getPrivKey() {
        return privKey;
    }

    public void setPrivKey(SntrupPrivKeyCore privKey) {
        this.privKey = privKey;
    }

    public SntrupPubKeyCore getPubKey() {
        return pubKey;
    }

    public void setPubKey(SntrupPubKeyCore pubKey) {
        this.pubKey = pubKey;
    }
}
