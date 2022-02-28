/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.sshattacker.attacks.config.AttackConfig;
import de.rub.nds.sshattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.sshattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** @param <AttConfigT> */
public abstract class Attacker<AttConfigT extends AttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** */
    protected AttConfigT config;

    private final Config baseConfig;

    /**
     * @param config
     * @param baseConfig
     */
    public Attacker(AttConfigT config, Config baseConfig) {
        this.config = config;
        this.baseConfig = baseConfig;
    }

    /** */
    public void attack() {
        LOGGER.debug("Attacking with: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return;
            }
        }
        executeAttack();
    }

    /** @return */
    public Boolean checkVulnerability() {
        LOGGER.debug("Checking: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return null;
            } else {
                LOGGER.debug("Can connect to server. Running vulnerability scan");
            }
        }
        return isVulnerable();
    }

    /** Executes a given attack. */
    protected abstract void executeAttack();

    /** @return */
    protected abstract Boolean isVulnerable();

    /** @return */
    public AttConfigT getConfig() {
        return config;
    }

    /** @return */
    public Config getSshConfig() {
        if (!config.hasDifferentConfig() && baseConfig == null) {
            return config.createConfig();
        } else {
            return config.createConfig(baseConfig);
        }
    }

    /** @return */
    public Config getBaseConfig() {
        return baseConfig /*.createCopy()*/;
    }

    /** @return */
    protected Boolean canConnect() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker =
                new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }
}
