package com.stepa7.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PremiumController {

    @GetMapping("/premium/dashboard")
    @PreAuthorize("hasRole('PREMIUM_USER')")
    public ResponseEntity<?> getPremiumDashboard() {
        return ResponseEntity.ok("Premium Dashboard");
    }
}
