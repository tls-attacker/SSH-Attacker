/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

/** */
public class EqualityErrorTranslator {

    /**
     * @param error
     * @param fingerprint1
     * @param fingerprint2
     * @return
     */
    public static String translation(
            EqualityError error,
            ResponseFingerprint fingerprint1,
            ResponseFingerprint fingerprint2) {
        StringBuilder builder = new StringBuilder();
        switch (error) {
            case MESSAGE_CLASS:
                builder.append("The server responds with different protocol messages.");
                break;
            case MESSAGE_COUNT:
                builder.append("The server responds with a different number of protocol messages.");
                break;
            case NONE:
                builder.append(
                        "The server shows no behaviour difference on the protocol / socket layer. The Server seems to be fine.");
                break;
            case SOCKET_STATE:
                builder.append(
                        "The server seems to occasionally move the TCP socket in different states.");
                break;
            case MESSAGE_CONTENT:
                builder.append("The server responded with different message contents");
                break;
            default:
                builder.append(error.toString());
        }
        return builder.toString();
    }

    private EqualityErrorTranslator() {}
}
