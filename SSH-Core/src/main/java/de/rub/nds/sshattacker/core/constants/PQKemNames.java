/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum PQKemNames {
    SNTRUP4591761("sntrup4591761", false),
    SNTRUP761("sntrup761", false),
    FRODOKEM1344("FrodoKEM-1344-SHAKE", true),
    FIRESABER("FireSaber-KEM", true),
    KYBER1024("Kyber1024", true);

    private String name;
    private boolean libOqs;

    PQKemNames(String name, boolean libOqs) {
        this.name = name;
        this.libOqs = libOqs;
    }

    public String getName() {
        return name;
    }

    public boolean hasLibOqsSupport() {
        return libOqs;
    }
}
