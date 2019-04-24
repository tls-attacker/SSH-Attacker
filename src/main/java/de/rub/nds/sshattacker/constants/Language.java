package de.rub.nds.sshattacker.constants;

public enum Language {
    NONE("");

    private String name;

    private Language(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
