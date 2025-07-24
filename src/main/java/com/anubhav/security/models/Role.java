package com.anubhav.security.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Set;
import java.util.List;

import static com.anubhav.security.models.Permission.*;

@RequiredArgsConstructor
public enum Role
{
    USER(Collections.emptySet()),
    ADMIN(Set.of(ADMIN_CREATE, ADMIN_READ, ADMIN_UPDATE, ADMIN_DELETE
            , MANAGER_READ, MANAGER_CREATE, MANAGER_UPDATE, MANAGER_DELETE)),
    MANAGER(Set.of(MANAGER_READ, MANAGER_CREATE, MANAGER_UPDATE, MANAGER_DELETE));

    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities()
    {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .toList();

        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
