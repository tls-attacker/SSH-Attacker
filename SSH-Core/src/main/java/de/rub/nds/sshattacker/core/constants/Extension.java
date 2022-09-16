/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Map;
import java.util.TreeMap;

public enum Extension {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#extension-names
     */
    // [ RFC 8308 ]
    SERVER_SIG_ALGS("server-sig-algs"),
    DELAY_COMPRESSION("delay-compression"),
    NO_FLOW_CONTROL("no-flow-control"),
    ELEVATION("elevation"),
    // Vendor extensions
    UNKNOWN(null);

    private final String name;

    private static final Map<String, Extension> map;

    static {
        map = new TreeMap<>();
        for (Extension extension : Extension.values()) {
            if (extension.name != null) {
                map.put(extension.name, extension);
            }
        }
    }

    Extension(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static Extension fromName(String name) {
        if (map.containsKey(name)) {
            return map.get(name);
        }
        return Extension.UNKNOWN;
    }
}
