/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public class CryptoConstants {

    public static final int X25519_POINT_SIZE = 32;
    public static final int X448_POINT_SIZE = 56;
    public static final int CHACHA20_KEY_SIZE = 32;
    public static final int SNTRUP761_PUBLIC_KEY_SIZE = 1158;
    public static final int SNTRUP761_CIPHERTEXT_SIZE = 1039;
    public static final int FRODOKEM1344_PUBLIC_KEY_SIZE = 21520;
    public static final int FRODOKEM1344_CIPHERTEXT_SIZE = 21632;
}
