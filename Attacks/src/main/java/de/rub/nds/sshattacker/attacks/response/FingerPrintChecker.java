/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.sshattacker.attacks.response;

/**
 *
 *
 */
public class FingerPrintChecker {

    /**
     *
     * @param  fingerprint1
     * @param  fingerprint2
     * @return
     */
    public static EqualityError checkEquality(ResponseFingerprint fingerprint1, ResponseFingerprint fingerprint2) {
        if (fingerprint1.getMessageList().size() == fingerprint2.getMessageList().size()) {
            for (int i = 0; i < fingerprint1.getMessageList().size(); i++) {
                if (!fingerprint1.getMessageList().get(i).toCompactString()
                    .equals(fingerprint2.getMessageList().get(i).toCompactString())) {
                    if (fingerprint1.getMessageList().get(i).getClass()
                        .equals(fingerprint2.getMessageList().get(i).getClass())) {
                        return EqualityError.MESSAGE_CONTENT;
                    } else {
                        return EqualityError.MESSAGE_CLASS;
                    }
                }
            }
        } else {
            return EqualityError.MESSAGE_COUNT;
        }
        if (fingerprint1.getSocketState() == fingerprint2.getSocketState()) {
            return EqualityError.NONE;
        } else {
            return EqualityError.SOCKET_STATE;
        }
    }

    private FingerPrintChecker() {
    }
}
