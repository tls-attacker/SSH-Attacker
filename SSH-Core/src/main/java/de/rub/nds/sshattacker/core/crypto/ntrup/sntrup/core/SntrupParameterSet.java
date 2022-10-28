/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

// Enum to define all possible Parameter Sets for sntrup as definded in https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
// Currently only kem/sntrup761 is used
public enum SntrupParameterSet {

    KEM_SNTRUP_761("kem/sntrup761", 761, 4591, 286);

    private final String name;
    private final int p;
    private final int q;
    private final int w;

    SntrupParameterSet(String name, int p, int q, int w) {
        this.name = name;
        this.p = p;
        this.q = q;
        this.w = w;
    }

    public int getP(){
        return p;
    }

    public int getQ(){
        return q;
    }

    public int getW(){
        return w;
    }

    @Override
    public String toString(){
        return name;
    }

}
