package com.example.core.security.userdetails;

import org.springframework.security.core.userdetails.UserDetails;

public interface SecurityUser extends UserDetails {
    Long getId();
}
