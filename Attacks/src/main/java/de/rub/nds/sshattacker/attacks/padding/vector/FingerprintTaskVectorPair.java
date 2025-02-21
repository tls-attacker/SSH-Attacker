/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.padding.vector;

import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;

/**
 * Combines a FingerprintTask with an attack vector
 *
 * @param <T> The type of the attack vector
 */
public record FingerprintTaskVectorPair<T extends Vector>(
        FingerPrintTask fingerPrintTask, T vector) {

    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{"
                + "fingerPrintTask="
                + fingerPrintTask
                + ", vector="
                + vector
                + '}';
    }
}
