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
import de.rub.nds.sshattacker.core.constants.ProtocolVersion;
import de.rub.nds.sshattacker.core.layer.constant.LayerConfiguration;

/** Config for Manger's attack */
public class BleichenbacherCommandConfig extends AttackConfig {

    /** Command line parameter to call the attack */
    public static final String ATTACK_COMMAND = "bb";

    @ParametersDelegate private final ClientDelegate clientDelegate;

    @ParametersDelegate private final AttackDelegate attackDelegate;

    @Parameter(
            names = "-encrypted_secret",
            required = false,
            description =
                    "Encrypted secret from the CMSG_SSH_SESSION_KEY "
                            + " message. You can retrieve this message from the Wireshark traffic. Find the"
                            + " secret message, right click on the \"Encrypted Secret\" value and copy this value as a Hex Stream.")
    private String encryptedSecret;

    @Parameter(
            names = {"-cookie", "-c"},
            required = false,
            description = "Cookie for SessionID Calculation")
    private String cookie;

    @Parameter(
            names = {"-benchmark", "-b"},
            description =
                    "If this value is set the Attack is Benchmarked, all Encrypted-Secrets are randomly generated")
    private boolean benchmark = false;

    /** How many rescans should be done */
    private int numberOfIterations = 3;

    public BleichenbacherCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(clientDelegate);
        addDelegate(attackDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setStopActionsAfterIOException(true);
        config.setWorkflowExecutorShouldClose(false);
        config.setProtocolVersion(ProtocolVersion.SSH1);
        config.setDefaultLayerConfiguration(LayerConfiguration.SSHV1);
        config.setClientVersion("SSH-1.7-OpenSSH_6.2p1");
        config.setDoNotEncryptMessages(true);
        config.setStopActionsAfterDisconnect(false);
        config.setStopReceivingAfterDisconnect(false);

        return config;
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public void setEncryptedSecret(String encryptedSecret) {
        this.encryptedSecret = encryptedSecret;
    }

    public int getNumberOfIterations() {
        return numberOfIterations;
    }

    public void setNumberOfIterations(int mapListDepth) {
        this.numberOfIterations = mapListDepth;
    }

    public boolean isBenchmark() {
        return benchmark;
    }

    public void setBenchmark(boolean benchmark) {
        this.benchmark = benchmark;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }
}
