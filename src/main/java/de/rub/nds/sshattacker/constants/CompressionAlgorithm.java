package de.rub.nds.sshattacker.constants;

public enum CompressionAlgorithm {
    NONE("none"),
    ZLIB("zlib"),
    ZLIB_OPENSSH_COM("zlib@openssh.com");

    private final String name;

    private CompressionAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
