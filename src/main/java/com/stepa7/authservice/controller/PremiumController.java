package com.stepa7.authservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PremiumController {

    @GetMapping("/premium/dashboard")
    @PreAuthorize("hasRole('PREMIUM_USER')")
    public String getPremiumDashboard(org.springframework.ui.Model model) {
        return "premium/dashboard";
    }
}
