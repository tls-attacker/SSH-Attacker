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

/**
 * Base class for Attacks that enables starting the attack/checking for the vulnerability.
 *
 * @param <AttConfigT> The Attack Config Type
 */
public abstract class Attacker<AttConfigT extends AttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected AttConfigT config;

    private final Config baseConfig;

    /**
     * @param config Attack specific config
     * @param baseConfig Base SSH config
     */
    public Attacker(AttConfigT config, Config baseConfig) {
        this.config = config;
        this.baseConfig = baseConfig;
    }

    /** Starts the attack after doing a connection check, if it is not disabled. */
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

    /**
     * @return True if server is vulnerable to the attack
     */
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

    /**
     * @return True if the server is vulnerable to the attack
     */
    protected abstract Boolean isVulnerable();

    public AttConfigT getConfig() {
        return config;
    }

    public Config getSshConfig() {
        if (!config.hasDifferentConfig() && baseConfig == null) {
            return config.createConfig();
        } else {
            return config.createConfig(baseConfig);
        }
    }

    /**
     * @return True if the server can be connected to
     */
    protected Boolean canConnect() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker =
                new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }
}
