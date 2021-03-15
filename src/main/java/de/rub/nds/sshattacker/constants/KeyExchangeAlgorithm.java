package de.rub.nds.sshattacker.constants;

public enum KeyExchangeAlgorithm {
    CURVE25519_SHA256("curve25519-sha256"),
    CURVE25519_SHA256_LIBSSH_ORG("curve25519-sha256@libssh.org"),
    DIFFIE_HELLMAN_GROUP1_SHA1("diffie-hellman-group1-sha1"),
    DIFFIE_HELLMAN_GROUP14_SHA1("diffie-hellman-group14-sha1"),
    DIFFIE_HELLMAN_GROUP14_SHA256("diffie-hellman-group14-sha256"),
    DIFFIE_HELLMAN_GROUP16_SHA512("diffie-hellman-group16-sha512"),
    DIFFIE_HELLMAN_GROUP18_SHA512("diffie-hellman-group18-sha512"),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1("diffie-hellman-group-exchange-sha1"),
    DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256("diffie-hellman-group-exchange-sha256"),
    ECDH_SHA2_NISTP256("ecdh-sha2-nistp256"),
    ECDH_SHA2_NISTP384("ecdh-sha2-nistp384"),
    ECDH_SHA2_NISTP521("ecdh-sha2-nistp521");

    private final String name;

    private KeyExchangeAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

}
