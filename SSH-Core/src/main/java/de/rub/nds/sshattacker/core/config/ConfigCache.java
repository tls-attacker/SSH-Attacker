/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import org.apache.commons.lang3.SerializationUtils;

public class ConfigCache {

    private final Config cachedConfig;

    public ConfigCache(Config cachedConfig) {
        this.cachedConfig = cachedConfig;
    }

    public Config getCachedCopy() {
        return SerializationUtils.clone(cachedConfig);
    }
}
