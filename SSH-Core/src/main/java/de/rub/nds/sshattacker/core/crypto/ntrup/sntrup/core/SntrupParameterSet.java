/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

// Enum to define all possible Parameter Sets for sntrup as definded in
// https://ntruprime.cr.yp.to/nist/ntruprime-20201007.pdf
// Currently only kem/sntrup761 is used
// in addition to the defined Parameters, the length of some encoded values is provided
public enum SntrupParameterSet {
    KEM_SNTRUP_761("kem/sntrup761", 761, 4591, 286, 1007, 1158, 191, 32),
    KEM_SNTRUP_4591761("kem/sntrup4591761", 761, 4591, 286, 1047, 1218, 191, 32);

    private final String name;
    private final int p;
    private final int q;
    private final int w;
    private final int encodedCiphertextLength;
    private final int encodedPublicKeyLength;
    private final int encodedSmallLength;
    private final int hashLength;

    @SuppressWarnings("SameParameterValue")
    SntrupParameterSet(
            String name,
            int p,
            int q,
            int w,
            int encodedCiphertextLength,
            int encodedPublicKeyLength,
            int encodedSmallLength,
            int hashLength) {

        this.name = name;
        this.p = p;
        this.q = q;
        this.w = w;
        this.encodedCiphertextLength = encodedCiphertextLength;
        this.encodedPublicKeyLength = encodedPublicKeyLength;
        this.encodedSmallLength = encodedSmallLength;
        this.hashLength = hashLength;
    }

    public int getP() {
        return p;
    }

    public int getQ() {
        return q;
    }

    public int getW() {
        return w;
    }

    public int getEncodedCiphertextLength() {
        return encodedCiphertextLength;
    }

    public int getEncodedPublicKeyLength() {
        return encodedPublicKeyLength;
    }

    public int getEncodedSmallLength() {
        return encodedSmallLength;
    }

    public int getHashLength() {
        return hashLength;
    }

    @Override
    public String toString() {
        return name;
    }
}
