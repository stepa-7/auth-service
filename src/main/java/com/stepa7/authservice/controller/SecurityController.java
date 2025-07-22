package com.stepa7.authservice.controller;

import com.stepa7.authservice.request.SigninRequest;
import com.stepa7.authservice.request.SignupRequest;
import com.stepa7.authservice.security.JwtCore;
import com.stepa7.authservice.user.User;
import com.stepa7.authservice.user.UserRepository;
import com.stepa7.authservice.user.UserRole;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.Cookie;


import java.util.Set;

@Controller
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
    ResponseEntity<?> signup(@ModelAttribute SignupRequest signupRequest) {
        if (userRepository.existsUserByLogin(signupRequest.getLogin())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different login");
        }
        if (userRepository.existsUserByMail(signupRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Choose different login");
        }
        String hashed = passwordEncoder.encode(signupRequest.getPassword());
        User user = new User();
        user.setLogin(signupRequest.getLogin());
        user.setMail(signupRequest.getEmail());
        user.setPassword(hashed);
        if (signupRequest.getRoles() == null || signupRequest.getRoles().isEmpty()) {
            user.setRole(Set.of(UserRole.GUEST));
        } else {
            user.setRole(signupRequest.getRoles());
        }
        userRepository.save(user);
        return ResponseEntity.ok("Success");
    }

    @PostMapping("/signin")
    public String signin(@ModelAttribute SigninRequest signinRequest, HttpServletResponse response) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signinRequest.getLogin(),
                    signinRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtCore.generateToken(authentication);

            Cookie jwtCookie = new Cookie("JWT", jwt);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(120);
            response.addCookie(jwtCookie);

            return "redirect:/profile";
        } catch (BadCredentialsException e) {
            return "redirect:/login?error=true";
        }
    }

    @PostMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("JWT", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);

        response.addCookie(cookie);
        SecurityContextHolder.clearContext();
        return "redirect:/login";
    }
}
