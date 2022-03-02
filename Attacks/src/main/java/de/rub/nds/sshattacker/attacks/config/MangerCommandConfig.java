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

/** */
public class MangerCommandConfig extends AttackConfig {

    /** */
    public static final String ATTACK_COMMAND = "manger";

    @ParametersDelegate private final ClientDelegate clientDelegate;

    @ParametersDelegate private final AttackDelegate attackDelegate;

    @Parameter(
            names = "-kex_algorithm",
            description =
                    "The key exchange algorithm that should be used: rsa2048_sha256 or rsa1024_sha1")
    private String kexAlgorithm;

    @Parameter(
            names = "-encrypted_secret",
            description =
                    "Encrypted secret from the RSA client "
                            + "key exchange message. You can retrieve this message from the Wireshark traffic. Find the RSA key "
                            + "exchange secret message, right click on the \"Encrypted Secret\" value and copy this value as a Hex Stream.")
    private String encryptedSecret;

    @Parameter(
            names = "-mock",
            description =
                    "If attack should be run against the MockOracle, which does not require a server")
    private boolean isMockAttack;

    @Parameter(
            names = "-mock_key_files",
            description =
                    "Name of the PKCS#8 encoded file that contains the private key used for the mock oracle. "
                            + "Ensure that the public key file has the same name, but ends in .pub.")
    private String mockKeyFileName;

    /** How many rescans should be done */
    private int numberOfIterations = 3;

    public MangerCommandConfig(GeneralDelegate delegate) {
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

        return config;
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public String getKexAlgorithm() {
        return kexAlgorithm;
    }

    public boolean isMockAttack() {
        return isMockAttack;
    }

    public String getMockKeyFileName() {
        return mockKeyFileName;
    }

    public int getNumberOfIterations() {
        return numberOfIterations;
    }

    public void setNumberOfIterations(int mapListDepth) {
        this.numberOfIterations = mapListDepth;
    }
}
