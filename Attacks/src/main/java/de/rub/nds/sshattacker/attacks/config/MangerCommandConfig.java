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
import de.rub.nds.sshattacker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;

/**
 *
 */
public class MangerCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "manger";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @ParametersDelegate
    private AttackDelegate attackDelegate;

    @Parameter(names = "-encrypted_secret",
        description = "Encrypted secret from the RSA client "
            + "key exchange message. You can retrieve this message from the Wireshark traffic. Find the RSA key "
            + "exchange secret message, right click on the \"Encrypted Secret\" value and copy this value as a Hex Stream.")
    private String encryptedSecret;

    /**
     * How many rescans should be done
     */
    private int numberOfIterations = 3;

    /**
     *
     * @param delegate
     */
    public MangerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(clientDelegate);
        addDelegate(attackDelegate);
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setStopActionsAfterIOException(true);
        config.setWorkflowExecutorShouldClose(false);

        return config;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    /**
     *
     * @return
     */
    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public int getNumberOfIterations() {
        return numberOfIterations;
    }

    public void setNumberOfIterations(int mapListDepth) {
        this.numberOfIterations = mapListDepth;
    }
}
