package com.stepa7.authservice.controller;

import com.stepa7.authservice.request.SigninRequest;
import com.stepa7.authservice.request.SignupRequest;
import com.stepa7.authservice.security.JwtCore;
import com.stepa7.authservice.token.RefreshToken;
import com.stepa7.authservice.token.RefreshTokenService;
import com.stepa7.authservice.user.User;
import com.stepa7.authservice.user.UserDetailsImpl;
import com.stepa7.authservice.user.UserRepository;
import com.stepa7.authservice.user.UserRole;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
    private RefreshTokenService refreshTokenService;
    @Value("${jwt.refreshExpirationMs:86400000}")
    private int refreshTokenDurationMs;

    @Autowired
    public SecurityController(UserRepository userRepository, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, JwtCore jwtCore, RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtCore = jwtCore;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute SignupRequest signupRequest) {
        if (userRepository.existsUserByLogin(signupRequest.getLogin())) {
            return "redirect:/signup?error=login_exists";
        }
        if (userRepository.existsUserByMail(signupRequest.getEmail())) {
            return "redirect:/signup?error=email_exists";
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
        return "redirect:/login?signup_success=true";
    }


    @PostMapping("/signin")
    public String signin(@ModelAttribute SigninRequest signinRequest, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signinRequest.getLogin(), signinRequest.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            User user = userRepository.findUserByLogin(signinRequest.getLogin()).orElseThrow();
            String accessToken = jwtCore.generateToken(authentication);

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            Cookie accessCookie = new Cookie("JWT", accessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setPath("/");
            accessCookie.setMaxAge(60);
            response.addCookie(accessCookie);

            Cookie refreshCookie = new Cookie("REFRESH_TOKEN", refreshToken.getToken());
            refreshCookie.setHttpOnly(true);
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge((int) (refreshTokenDurationMs));
            response.addCookie(refreshCookie);

            return "redirect:/profile";
        } catch (BadCredentialsException e) {
            return "redirect:/login?error=true";
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(name = "REFRESH_TOKEN", required = false) String refreshTokenCookie,
                                          HttpServletResponse response) {
        if (refreshTokenCookie == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is missing");
        }

        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenCookie);
        if (refreshToken == null || refreshTokenService.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is invalid or expired");
        }

        User user = refreshToken.getUser();
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        String newAccessToken = jwtCore.generateToken(authentication);

        Cookie newAccessCookie = new Cookie("JWT", newAccessToken);
        newAccessCookie.setHttpOnly(true);
        newAccessCookie.setPath("/");
        newAccessCookie.setMaxAge(120);
        response.addCookie(newAccessCookie);

        return ResponseEntity.ok("Access token refreshed");
    }

    @PostMapping("/logout")
    public String logout(@CookieValue(name = "REFRESH_TOKEN", required = false) String refreshTokenCookie,
                                    HttpServletResponse response) {
        if (refreshTokenCookie != null) {
            refreshTokenService.deleteByToken(refreshTokenCookie);
        }

        Cookie accessCookie = new Cookie("JWT", "");
        accessCookie.setHttpOnly(true);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(0);
        response.addCookie(accessCookie);

        Cookie refreshCookie = new Cookie("REFRESH_TOKEN", "");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);

        SecurityContextHolder.clearContext();
        return "redirect:/login";
    }
}
