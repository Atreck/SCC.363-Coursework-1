package main;

import java.io.Serializable;
import java.util.HashSet;

public class Context implements Serializable {

    private String group;
    private HashSet<Long> permissions;

    public Context(String group) { this.group = group; }

    public Context(String group, HashSet<Long> permissions) {
        this.group = group;
        this.permissions = permissions;
    }

    public String getGroup() {
        return group;
    }

    public HashSet<Long> getPermissions() {
        return permissions;
    }
}
