package de.rub.nds.sshattacker.constants;

public enum CompressionAlgorithm {
    none("none"),
    zlib("zlib"),
    zlib_openssh_com("zlib@openssh.com");

    private final String name;

    private CompressionAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
