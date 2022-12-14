/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum OpenQuantumSafeKemNames {
    // Not supported in openquantumsafe
    SNTRUP4591761("sntrup4591761"),
    SNTRUP761("sntrup761"),
    FRODOKEM1344("FrodoKEM-1344-SHAKE");

    private String name;

    private OpenQuantumSafeKemNames(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
