/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.exception;

/** */
public class AttackFailedException extends RuntimeException {

    /** */
    public AttackFailedException() {}

    /** @param message */
    public AttackFailedException(String message) {
        super(message);
    }

    /**
     * @param message
     * @param cause
     */
    public AttackFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    /** @param cause */
    public AttackFailedException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public AttackFailedException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
