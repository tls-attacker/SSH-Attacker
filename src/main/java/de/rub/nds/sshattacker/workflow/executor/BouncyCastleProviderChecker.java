package de.rub.nds.sshattacker.workflow.executor;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleProviderChecker {

    static boolean isLoaded() {
        for (Provider p : Security.getProviders()) {
            if (p.getClass().equals(BouncyCastleProvider.class)) {
                return true;
            }
        }
        return false;
    }
}
