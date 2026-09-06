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
                          RefreshTokenService refreshTokenService, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.emailService = emailService;
    }

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
                .build();
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        User user = userRepository.findByEmail(request.get("email"))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.get("password"), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        return issueTokens(user);
    }

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

            // User ရှိပြီးသားဆိုလျှင် ပြန်ယူမည်၊ မရှိသေးပါက ဆောက်မည်
            User user = userRepository.findByEmail(email)
                    .map(existingUser -> {
                        // Profile picture သို့မဟုတ် Name ပြောင်းသွားပါက ခေတ္တ Update လုပ်ပေးနိုင်သည်
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
                                    .build()
                    ));

            return issueTokens(user);

        } catch (Exception e) {
            e.printStackTrace(); // Console Log တွင် Error အတိအကျ ကြည့်ရန်
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Google Authentication Failed: " + e.getMessage());
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        String oldRefreshToken = jwtUtils.getRefreshTokenFromCookies(request);

        if (oldRefreshToken == null || oldRefreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token missing in cookie");
        }

        try {
            RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(oldRefreshToken);
            String newAccessToken = jwtUtils.generateAccessToken(newRefreshToken.getUser().getEmail());

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

    @PutMapping("/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        try {
            // JwtUtils သို့မဟုတ် SecurityContextHolder မှတစ်ဆင့် Login ဝင်ထားသော User ရဲ့ Email ကို ယူမည်
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
            }

            String token = authHeader.substring(7);
            String email = jwtUtils.getEmailFromToken(token); // JwtUtils ထဲတွင် getEmailFromToken Method ရှိရမည်

            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Name သို့မဟုတ် Profile Picture ကို Update ပြုလုပ်ခြင်း
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

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest httpRequest) {
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        String token = authHeader.substring(7);
        String email = jwtUtils.getEmailFromToken(token);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "fullName", user.getFullName() != null ? user.getFullName() : "",
                "profilePicture", user.getProfilePicture() != null ? user.getProfilePicture() : "",
                "provider", user.getProvider()
        ));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User user = userRepository.findByEmail(email).orElse(null);

        // Security ရာဇဝင်အရ Email မရှိသော်လည်း Request အောင်မြင်ကြောင်း ပြန်ပြနိုင်သည် (Email Enumeration ကာကွယ်ရန်)
        if (user != null) {
            // ဂဏန်း ၆ လုံးပါ OTP Generate လုပ်ခြင်း
            String otp = String.valueOf((int) ((Math.random() * (900000)) + 100000));

            user.setResetPasswordToken(otp);
            user.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(10)); // ၁၀ မိနစ် သက်တမ်း
            userRepository.save(user);

            emailService.sendResetPasswordOtp(email, otp);
        }

        return ResponseEntity.ok("If the email exists, a reset code has been sent.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String otp = request.get("otp");
        String newPassword = request.get("newPassword");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // OTP မှန်မမှန် စစ်ဆေးခြင်း
        if (user.getResetPasswordToken() == null || !user.getResetPasswordToken().equals(otp)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid OTP code");
        }

        // OTP သက်တမ်း ကုန်/မကုန် စစ်ဆေးခြင်း
        if (user.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("OTP code has expired");
        }

        // Password အသစ် ပြောင်းလဲပြီး OTP များကို ပြန်ဖျက်ခြင်း
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetPasswordToken(null);
        user.setResetPasswordTokenExpiry(null);
        userRepository.save(user);

        return ResponseEntity.ok("Password reset successfully. You can now login with your new password.");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie cleanCookie = jwtUtils.getCleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body("Logged out successfully");
    }

    private ResponseEntity<?> issueTokens(User user) {
        String accessToken = jwtUtils.generateAccessToken(user.getEmail());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        ResponseCookie refreshTokenCookie = jwtUtils.generateRefreshTokenCookie(refreshToken.getToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(Map.of("accessToken", accessToken, "userId", user.getId(), "email", user.getEmail()));
    }
}