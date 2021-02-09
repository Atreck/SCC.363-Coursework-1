package main;

import java.io.Serializable;
import java.util.HashSet;

public class Context implements Serializable {

    private String group;
    private long active;
    private long locked;
    private HashSet<Long> permissions;

    public Context(String group) { this.group = group; }

    public Context(String group, long active, long locked, HashSet<Long> permissions) {
        this.group = group;
        this.active = active;
        this.locked = locked;
        this.permissions = permissions;
    }

    public String getGroup() {
        return group;
    }

    public HashSet<Long> getPermissions() {
        return permissions;
    }

    public long getActive() {
        return active;
    }

    public long getLocked() {
        return locked;
    }
}
