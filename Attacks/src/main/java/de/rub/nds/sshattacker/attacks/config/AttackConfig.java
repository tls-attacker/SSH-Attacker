/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.sshattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.sshattacker.core.config.SSHDelegateConfig;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;

/**
 *
 */
public abstract class AttackConfig extends SSHDelegateConfig {

    @Parameter(names = { "-skipConnectionCheck", "-skip_connection_check" },
        description = "If set to true the Attacker will not check if the " + "target is reachable.")
    private boolean skipConnectionCheck = false;

    /**
     * @param delegate
     */
    public AttackConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    /**
     * @return
     */
    public abstract boolean isExecuteAttack();

    /**
     * @return
     */
    public boolean isSkipConnectionCheck() {
        return skipConnectionCheck;
    }

    /**
     * @param skipConnectionCheck
     */
    public void setSkipConnectionCheck(boolean skipConnectionCheck) {
        this.skipConnectionCheck = skipConnectionCheck;
    }
}
