/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

/** Translates equality errors into human-readable form */
public class EqualityErrorTranslator {

    /**
     * @param error The equality error to be translated
     * @return A human-readable message that describes the equality error
     */
    public static String translation(EqualityError error) {
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
                builder.append(error);
        }
        return builder.toString();
    }

    private EqualityErrorTranslator() {}
}
