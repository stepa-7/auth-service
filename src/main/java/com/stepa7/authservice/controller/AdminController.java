package com.stepa7.authservice.controller;

import com.stepa7.authservice.user.User;
import com.stepa7.authservice.user.UserRepository;
import com.stepa7.authservice.user.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Set;

@Controller
public class AdminController {
    private UserRepository userRepository;

    @Autowired
    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public String getUsersPage(org.springframework.ui.Model model) {
        model.addAttribute("users", userRepository.findAll());
        model.addAttribute("allRoles", UserRole.values());
        return "admin/users";
    }

    @PutMapping("/user/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserRoles(@PathVariable Long id, @RequestBody Set<UserRole> roles) {
        User user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        user.setRole(roles);
        userRepository.save(user);
        return ResponseEntity.ok("Roles updated");
    }

}
