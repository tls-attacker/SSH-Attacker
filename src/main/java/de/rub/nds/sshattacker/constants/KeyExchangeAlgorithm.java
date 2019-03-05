package de.rub.nds.sshattacker.constants;

public enum KeyExchangeAlgorithm {
    curve25519_sha256("curve25519-sha256"),
    curve25519_sha256_libssh_org("curve25519-sha256@libssh.org"),
    diffie_hellman_group1_sha1("diffie-hellman-group1-sha1"),
    diffie_hellman_group14_sha1("diffie-hellman-group14-sha1"),
    diffie_hellman_group14_sha256("diffie-hellman-group14-sha256"),
    diffie_hellman_group16_sha512("diffie-hellman-group16-sha512"),
    diffie_hellman_group18_sha512("diffie-hellman-group18-sha512"),
    diffie_hellman_group_exchange_sha1("diffie-hellman-group-exchange-sha1"),
    diffie_hellman_group_exchange_sha256("diffie-hellman-group-exchange-sha256"),
    ecdh_sha2_nistp256("ecdh-sha2-nistp256"),
    ecdh_sha2_nistp384("ecdh-sha2-nistp384"),
    ecdh_sha2_nistp521("ecdh-sha2-nistp521");

    private final String name;

    private KeyExchangeAlgorithm(String name) {
        this.name = name;
    }
    
    @Override
    public String toString(){
        return name;
    }

}
