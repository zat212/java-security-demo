package org.myjavasecurity.controller;

import org.myjavasecurity.entity.User;
import org.myjavasecurity.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Any authenticated user can view other user profiles
    @GetMapping("/{id}")
    public ResponseEntity<?> getUserProfile(@PathVariable Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(null); // Never leak the password hash
        return ResponseEntity.ok(user);
    }

    // User can update ONLY their own profile
    @PutMapping("/{id}")
    public ResponseEntity<?> updateProfile(@PathVariable Long id,
                                           @RequestBody Map<String, String> updates,
                                           Authentication authentication) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getEmail().equals(authentication.getName())) {
            return ResponseEntity.status(403).body("Forbidden: You can only edit your own profile!");
        }

        if (updates.containsKey("fullName")) user.setFullName(updates.get("fullName"));
        if (updates.containsKey("bio")) user.setBio(updates.get("bio"));

        userRepository.save(user);
        return ResponseEntity.ok(user);
    }
}