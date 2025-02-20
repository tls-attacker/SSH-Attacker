/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;

public enum KemAlgorithm {
    SNTRUP761("sntrup761", 1158, 1039, "SNTRUPrime", SNTRUPrimeParameterSpec.sntrup761),
    MLKEM768("mlkem768", 1184, 1088, "ML-KEM", MLKEMParameterSpec.ml_kem_768),
    MLKEM1024("mlkem1024", 1568, 1568, "ML-KEM", MLKEMParameterSpec.ml_kem_1024);

    private final String name;
    private final int publicKeySize;
    private final int encapsulationSize;
    private final String javaName;
    private final AlgorithmParameterSpec parameterSpec;

    KemAlgorithm(
            String name,
            int publicKeySize,
            int encapsulationSize,
            String javaName,
            AlgorithmParameterSpec parameterSpec) {
        this.name = name;
        this.publicKeySize = publicKeySize;
        this.encapsulationSize = encapsulationSize;
        this.javaName = javaName;
        this.parameterSpec = parameterSpec;
    }

    public String getName() {
        return name;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getEncapsulationSize() {
        return encapsulationSize;
    }

    public String getJavaName() {
        return javaName;
    }

    public AlgorithmParameterSpec getParameterSpec() {
        return parameterSpec;
    }
}
