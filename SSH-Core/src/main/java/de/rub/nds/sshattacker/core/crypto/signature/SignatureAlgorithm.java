package de.rub.nds.sshattacker.core.crypto.signature;

public enum SignatureAlgorithm {

    /*
     * Sources:
     * Default Algorithms https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/Signature.html
     */
    SHA1_WITH_DSA("SHA1_WITH_DSA", "SHA1withDSA"),
    SHA256_WITH_DSA("SHA256_WITH_DSA", "SHA256withDSA"),
    SHA1_WITH_RSA("SHA1_WITH_RSA","SHA1withRSA"),
    SHA256_WITH_RSA("SHA256_WITH_RSA", "SHA256withRSA");


    private final String name;
    private final String javaName;

    SignatureAlgorithm(String name, String javaName) {
        this.name = name;
        this.javaName = javaName;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public String getJavaName() {
        return javaName;
    }
}
