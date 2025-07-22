package com.stepa7.authservice.request;

import com.stepa7.authservice.user.UserRole;
import lombok.Data;

import java.util.Set;

@Data
public class SignupRequest {
    private String login;
    private String password;
    private String email;
    private Set<UserRole> roles;
}
