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
import org.myjavasecurity.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    @Value("${google.client-id}")
    private String googleClientId;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtils jwtUtils,
                          RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
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