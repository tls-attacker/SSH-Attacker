/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.sshattacker.core.config.SshDelegateConfig;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.sshattacker.core.config.delegate.TimeoutDelegate;

/**
 * Base Config for attacks that can be extended to support additional configuration options All
 * attacks should define an attack command to be executable.
 */
public abstract class AttackConfig extends SshDelegateConfig {

    @Parameter(
            names = {"-skipConnectionCheck", "-skip_connection_check"},
            description =
                    "If set to true the Attacker will not check if the " + "target is reachable.")
    private boolean skipConnectionCheck = false;

    @ParametersDelegate private final TimeoutDelegate timeoutDelegate;

    public AttackConfig(GeneralDelegate delegate) {
        super(delegate);
        this.timeoutDelegate = new TimeoutDelegate();
        addDelegate(timeoutDelegate);
    }

    public abstract boolean isExecuteAttack();

    public boolean isSkipConnectionCheck() {
        return skipConnectionCheck;
    }

    public void setSkipConnectionCheck(boolean skipConnectionCheck) {
        this.skipConnectionCheck = skipConnectionCheck;
    }
}
