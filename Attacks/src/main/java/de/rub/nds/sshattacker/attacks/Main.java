/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.JCommander.Builder;
import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.attacks.config.MangerCommandConfig;
import de.rub.nds.sshattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.sshattacker.attacks.impl.Attacker;
import de.rub.nds.sshattacker.attacks.impl.MangerAttacker;
import de.rub.nds.sshattacker.core.config.SshDelegateConfig;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    private Main() {
        super();
    }

    public static void main(String[] args) {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Builder builder = JCommander.newBuilder().addObject(generalDelegate);

        MangerCommandConfig mangerTest = new MangerCommandConfig(generalDelegate);
        builder.addCommand(MangerCommandConfig.ATTACK_COMMAND, mangerTest);

        JCommander jc = builder.build();

        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            String parsedCommand = ex.getJCommander().getParsedCommand();
            if (parsedCommand != null) {
                ex.getJCommander().getUsageFormatter().usage(parsedCommand);
            } else {
                ex.usage();
            }
            return;
        }

        if (jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.getUsageFormatter().usage(jc.getParsedCommand());
            return;
        }

        Attacker<? extends SshDelegateConfig> attacker = null;

        // Insert new attack commands here
        //noinspection SwitchStatementWithTooFewBranches
        switch (jc.getParsedCommand()) {
            case MangerCommandConfig.ATTACK_COMMAND:
                attacker = new MangerAttacker(mangerTest, mangerTest.createConfig());
                break;
            default:
                break;
        }

        if (attacker == null) {
            throw new ConfigurationException("Command not found");
        }

        if (attacker.getConfig().isExecuteAttack()) {
            attacker.attack();
        } else {
            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:{}", result);
                } else if (Objects.equals(result, Boolean.FALSE)) {
                    CONSOLE.info("Vulnerable:{}", result);
                } else {
                    CONSOLE.warn("Vulnerable: Uncertain");
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
    }
}
