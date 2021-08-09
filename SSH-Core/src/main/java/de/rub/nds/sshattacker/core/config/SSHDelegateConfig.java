/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.sshattacker.core.config.delegate.Delegate;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSHDelegateConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<Delegate> delegateList;

    @ParametersDelegate private final GeneralDelegate generalDelegate;

    @Parameter(
            names = "-config",
            description = "This parameter allows you to specify a default SshConfig")
    private String defaultConfig = null;

    public SSHDelegateConfig(GeneralDelegate delegate) {
        delegateList = new LinkedList<>();
        this.generalDelegate = delegate;
        if (delegate != null) {
            delegateList.add(generalDelegate);
        }
    }

    public final void addDelegate(Delegate delegate) {
        delegateList.add(delegate);
    }

    public Delegate getDelegate(Class<? extends Delegate> delegateClass) {
        for (Delegate delegate : getDelegateList()) {
            if (delegate.getClass().equals(delegateClass)) {
                return delegate;
            }
        }
        return null;
    }

    public List<Delegate> getDelegateList() {
        return Collections.unmodifiableList(delegateList);
    }

    public GeneralDelegate getGeneralDelegate() {
        return generalDelegate;
    }

    public Config createConfig(Config baseConfig) {
        for (Delegate delegate : getDelegateList()) {
            delegate.applyDelegate(baseConfig);
        }
        return baseConfig;
    }

    public final boolean hasDifferentConfig() {
        return defaultConfig != null;
    }

    public Config createConfig() {
        Config config;
        if (defaultConfig != null) {
            File configFile = new File(defaultConfig);
            if (configFile.exists()) {
                config = Config.createConfig(configFile);
            } else {
                throw new ParameterException("Could not find config file: " + defaultConfig);
            }
        } else {
            config = Config.createConfig();
        }

        return createConfig(config);
    }
}
