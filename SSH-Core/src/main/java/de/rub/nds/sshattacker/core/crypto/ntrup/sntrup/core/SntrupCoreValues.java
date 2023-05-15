/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

@SuppressWarnings("StandardVariableNames")
public class SntrupCoreValues {
    private R g;
    private R3 gInv;
    private Short f;
    private RQ f3;
    private RQ f3Inv;
    private RQ h;
    private Short roh;

    public SntrupCoreValues(R g, R3 gInv, Short f, RQ f3, RQ f3Inv, RQ h, Short roh) {
        super();
        this.g = g;
        this.gInv = gInv;
        this.f = f;
        this.f3 = f3;
        this.f3Inv = f3Inv;
        this.h = h;
        this.roh = roh;
    }

    public R getG() {
        return g;
    }

    public void setG(R g) {
        this.g = g;
    }

    public R3 getgInv() {
        return gInv;
    }

    public void setgInv(R3 gInv) {
        this.gInv = gInv;
    }

    public Short getF() {
        return f;
    }

    public void setF(Short f) {
        this.f = f;
    }

    public RQ getF3() {
        return f3;
    }

    public void setF3(RQ f3) {
        this.f3 = f3;
    }

    public RQ getF3Inv() {
        return f3Inv;
    }

    public void setF3Inv(RQ f3Inv) {
        this.f3Inv = f3Inv;
    }

    public RQ getH() {
        return h;
    }

    public void setH(RQ h) {
        this.h = h;
    }

    public Short getRoh() {
        return roh;
    }

    public void setRoh(Short roh) {
        this.roh = roh;
    }
}
