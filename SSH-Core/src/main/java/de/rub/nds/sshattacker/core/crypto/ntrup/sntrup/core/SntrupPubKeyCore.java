/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

public class SntrupPubKeyCore {
    
    private RQ h;

    
    public SntrupPubKeyCore(RQ h) {
        this.h = h;
    }

    public RQ getH() {
        return h;
    }

    public void setH(RQ h) {
        this.h = h;
    }

    
}
