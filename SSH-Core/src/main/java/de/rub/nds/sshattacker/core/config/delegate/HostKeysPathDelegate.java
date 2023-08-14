/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.sshattacker.core.config.Config;
import java.util.ArrayList;
import java.util.List;

public class HostKeysPathDelegate extends Delegate {

    @Parameter(
            names = "-host_keys",
            description =
                    "Comma seperated list of paths to host keys (no white-space). "
                            + "If no host keys are provided, the default host keys will be used.")
    private List<String> paths = new ArrayList<>();

    public List<String> getHostKeyPaths() {
        return paths;
    }

    public void setHostKeyPaths(List<String> paths) {
        this.paths = paths;
    }

    @Override
    public void applyDelegate(Config config) {
        if (paths != null && !paths.isEmpty()) {
            config.setHostKeyPaths(paths);
            // after overwriting the list of paths, we need to load the host keys again
            config.loadHostKeys();
        }
    }
}
