/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/** These values are also used for hash-algorithm-list of SFTP check-file messages */
public enum HashAlgorithm {
    /*
     * Sources:
     * - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-3
     * - https://datatracker.ietf.org/doc/html/rfc1321
     */
    // [ RFC 1321 ]
    MD5("md5"),
    // [ FIPS-180-2 ]
    SHA_1("sha1"),
    SHA_224("sha224"),
    SHA_256("sha256"),
    SHA_384("sha384"),
    SHA_512("sha512"),
    // [ ISO.3309.1991 ]
    CRC32("crc32");

    private final String name;

    public static final Map<String, HashAlgorithm> map;

    static {
        Map<String, HashAlgorithm> mutableMap = new TreeMap<>();
        for (HashAlgorithm algorithm : values()) {
            mutableMap.put(algorithm.name, algorithm);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    HashAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static HashAlgorithm fromName(String name) {
        return map.get(name);
    }
}
