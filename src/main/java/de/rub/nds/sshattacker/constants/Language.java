package de.rub.nds.sshattacker.constants;

public enum Language {
    none("");

    private String name;

    private Language(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
