package com.stepa7.authservice;

import lombok.Data;

@Data
public class SignupRequest {
    private String login;
    private String mail;
    private String password;
}
