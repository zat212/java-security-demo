package org.myjavasecurity.controller;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.servlet.http.HttpServletRequest;
import org.myjavasecurity.entity.RefreshToken;
import org.myjavasecurity.entity.User;
import org.myjavasecurity.repository.UserRepository;
import org.myjavasecurity.security.JwtUtils;
import org.myjavasecurity.service.EmailService;
import org.myjavasecurity.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final EmailService emailService;

    @Value("${google.client-id}")
    private String googleClientId;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtils jwtUtils,
                          RefreshTokenService refreshTokenService,
                          EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.emailService = emailService;
    }

    // 1. Public User Registration
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(request.get("password")))
                .fullName(request.get("fullName"))
                .provider(User.AuthProvider.LOCAL)
                .role(User.Role.USER) // Default role သတ်မှတ်ပေးထားပါသည်
                .build();
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    // 2. Admin Registration (ADMIN Role ရှိသူသာ ခေါ်ယူခွင့်ရှိမည်)
    @PostMapping("/admin/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> registerAdmin(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        User admin = User.builder()
                .email(email)
                .password(passwordEncoder.encode(request.get("password")))
                .fullName(request.get("fullName"))
                .provider(User.AuthProvider.LOCAL)
                .role(User.Role.ADMIN) // Role ကို ADMIN ဟု သတ်မှတ်ပါသည်
                .build();
        userRepository.save(admin);

        return ResponseEntity.status(HttpStatus.CREATED).body("Admin registered successfully");
    }

    // 3. Email/Password Login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        User user = userRepository.findByEmail(request.get("email"))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getPassword() == null || !passwordEncoder.matches(request.get("password"), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Password is wrong!!");
        }

        return issueTokens(user);
    }

    // 4. Google Login
    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestBody Map<String, String> request) {
        try {
            String idTokenString = request.get("idToken");
            if (idTokenString == null || idTokenString.isBlank()) {
                return ResponseEntity.badRequest().body("ID Token is missing");
            }

            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                System.err.println("Google Token verification failed: idToken is null");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Google Token");
            }

            GoogleIdToken.Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            String name = (String) payload.get("name");
            String picture = (String) payload.get("picture");

            User user = userRepository.findByEmail(email)
                    .map(existingUser -> {
                        if (existingUser.getProfilePicture() == null) {
                            existingUser.setProfilePicture(picture);
                            return userRepository.save(existingUser);
                        }
                        return existingUser;
                    })
                    .orElseGet(() -> userRepository.save(
                            User.builder()
                                    .email(email)
                                    .fullName(name)
                                    .profilePicture(picture)
                                    .provider(User.AuthProvider.GOOGLE)
                                    .role(User.Role.USER) // Google user အား Default USER role ပေးပါသည်
                                    .build()
                    ));

            return issueTokens(user);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Google Authentication Failed: " + e.getMessage());
        }
    }

    // 5. Refresh Token Endpoint
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        String oldRefreshToken = jwtUtils.getRefreshTokenFromCookies(request);

        if (oldRefreshToken == null || oldRefreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Missing Password");
        }

        try {
            RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(oldRefreshToken);

            // role ကို user ထံမှ ရယူ၍ JWT Token ထုတ်ပေးပါမည်
            String roleStr = newRefreshToken.getUser().getRole().name();
            String newAccessToken = jwtUtils.generateAccessToken(newRefreshToken.getUser().getEmail(), roleStr);

            ResponseCookie newCookie = jwtUtils.generateRefreshTokenCookie(newRefreshToken.getToken());

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, newCookie.toString())
                    .body(Map.of("accessToken", newAccessToken));

        } catch (SecurityException e) {
            ResponseCookie cleanCookie = jwtUtils.getCleanRefreshTokenCookie();
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                    .body(e.getMessage());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    // 6. Profile Update
    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        try {
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
            }

            String token = authHeader.substring(7);
            String email = jwtUtils.getEmailFromToken(token);

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (request.containsKey("fullName")) {
                user.setFullName(request.get("fullName"));
            }
            if (request.containsKey("profilePicture")) {
                user.setProfilePicture(request.get("profilePicture"));
            }
            userRepository.save(user);
            return ResponseEntity.ok(Map.of(
                    "message", "Profile updated successfully",
                    "fullName", user.getFullName(),
                    "email", user.getEmail(),
                    "profilePicture", user.getProfilePicture() != null ? user.getProfilePicture() : ""
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Profile update failed: " + e.getMessage());
        }
    }

    // 7. Get Current Authenticated User Details
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest httpRequest) {
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }
        System.out.println("this is working always");
        String token = authHeader.substring(7);
        String email = jwtUtils.getEmailFromToken(token);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "fullName", user.getFullName() != null ? user.getFullName() : "",
                "profilePicture", user.getProfilePicture() != null ? user.getProfilePicture() : "",
                "provider", user.getProvider(),
                "role", user.getRole().name()
        ));
    }

    // 8. Forgot Password (OTP Generation)
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null) {
            String otp = String.valueOf((int) ((Math.random() * (900000)) + 100000));

            user.setResetPasswordToken(otp);
            user.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(10));
            userRepository.save(user);

            emailService.sendResetPasswordOtp(email, otp);
        }

        return ResponseEntity.ok("If the email exists, a reset code has been sent.");
    }

    // 9. Reset Password using OTP
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String otp = request.get("otp");
        String newPassword = request.get("newPassword");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getResetPasswordToken() == null || !user.getResetPasswordToken().equals(otp)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid OTP code");
        }

        if (user.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("OTP code has expired");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetPasswordToken(null);
        user.setResetPasswordTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok("Password reset successfully. You can now login with your new password.");
    }

    // 10. Logout Endpoint
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie cleanCookie = jwtUtils.getCleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body("Logged out successfully");
    }

    // Helper Method to Issue Access and Refresh Tokens
    private ResponseEntity<?> issueTokens(User user) {
        // generateAccessToken ခေါ်ဆိုရာတွင် Email အပြင် Role ပါ ထည့်သွင်းပေးပါသည်
        String accessToken = jwtUtils.generateAccessToken(user.getEmail(), user.getRole().name());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        ResponseCookie refreshTokenCookie = jwtUtils.generateRefreshTokenCookie(refreshToken.getToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(Map.of(
                        "accessToken", accessToken,
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "role", user.getRole().name()
                ));
    }
}