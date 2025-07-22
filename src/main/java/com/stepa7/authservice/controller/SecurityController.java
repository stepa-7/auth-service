package com.stepa7.authservice.controller;

import com.stepa7.authservice.request.SigninRequest;
import com.stepa7.authservice.request.SignupRequest;
import com.stepa7.authservice.security.JwtCore;
import com.stepa7.authservice.user.User;
import com.stepa7.authservice.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {
    private UserRepository userRepository;
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;
    private JwtCore jwtCore;

    @Autowired
    public SecurityController(UserRepository userRepository, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, JwtCore jwtCore) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtCore = jwtCore;
    }

    @PostMapping("/signup")
    ResponseEntity<?> signup(@RequestBody SignupRequest signupRequest) {
        if (userRepository.existsUserByLogin(signupRequest.getLogin())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different login");
        }
        if (userRepository.existsUserByMail(signupRequest.getMail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different login");
        }
        String hashed = passwordEncoder.encode(signupRequest.getPassword());
        User user = new User();
        user.setLogin(signupRequest.getLogin());
        user.setMail(signupRequest.getMail());
        user.setPassword(hashed);
        userRepository.save(user);
        return ResponseEntity.ok("Success");
    }

    @PostMapping("/signin")
    ResponseEntity<?> signin(@RequestBody SigninRequest signinRequest) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signinRequest.getLogin(),
                    signinRequest.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtCore.generateToken(authentication);
        return ResponseEntity.ok(jwt);
    }

}
