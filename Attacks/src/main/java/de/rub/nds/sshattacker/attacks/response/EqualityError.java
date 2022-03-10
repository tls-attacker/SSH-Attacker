/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

/** Represents errors that can occur when comparing Fingerprints */
public enum EqualityError {

    /** No error */
    NONE,
    /** Different socket state */
    SOCKET_STATE,
    /** Number of messages is not equal */
    MESSAGE_COUNT,
    /** Different messages */
    MESSAGE_CLASS,
    /** Same message class, but different content */
    MESSAGE_CONTENT
}
