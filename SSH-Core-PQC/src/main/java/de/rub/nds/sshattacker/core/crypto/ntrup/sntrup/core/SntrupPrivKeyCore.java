/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

public class SntrupPrivKeyCore {
    private Short f;
    private R g;
    private R3 gInv;
    private RQ f3;
    private RQ f3Inv;

    public SntrupPrivKeyCore(Short f, R3 gInv) {
        this.f = f;
        this.gInv = gInv;
        this.f3 = RQ.multiply(3, f);
        this.f3Inv = RQ.invert(f3);
    }

    public SntrupPrivKeyCore(Short f, RQ f3, R3 gInv) {
        this.f3 = f3;
        this.f = f;
        this.gInv = gInv;
    }

    public SntrupPrivKeyCore(Short f, RQ f3, RQ f3Inv, R g, R3 gInv) {
        this.f3 = f3;
        this.f3Inv = f3Inv;
        this.f = f;
        this.gInv = gInv;
        this.g = g;
    }

    public R getG() {
        return g;
    }

    public Short getF() {
        return f;
    }

    public void setF(Short f) {
        this.f = f;
    }

    public R3 getgInv() {
        return gInv;
    }

    public void setgInv(R3 gInv) {
        this.gInv = gInv;
    }

    public RQ getF3() {
        if (f3 == null) {
            f3 = RQ.multiply(3, f);
        }
        return f3;
    }

    public RQ getF3Inv() {
        return f3Inv;
    }
}
