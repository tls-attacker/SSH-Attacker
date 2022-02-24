/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.padding.vector;

import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;

public class FingerprintTaskVectorPair<T extends Vector> {

    private final FingerPrintTask fingerPrintTask;

    private final T vector;

    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, T vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    public T getVector() {
        return vector;
    }

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
