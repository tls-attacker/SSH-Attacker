/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.padding;

import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;

/** Combines a vector with the server's response to it */
public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final Vector vector;

    private VectorResponse() {
        fingerprint = null;
        vector = null;
    }

    public VectorResponse(Vector vector, ResponseFingerprint fingerprint) {
        this.vector = vector;
        this.fingerprint = fingerprint;
    }

    public Vector getVector() {
        return vector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", vector=" + vector + '}';
    }
}
