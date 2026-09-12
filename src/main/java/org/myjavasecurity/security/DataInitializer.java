package org.myjavasecurity.security;

import org.myjavasecurity.entity.User;
import org.myjavasecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (userRepository.findByEmail("admin@example.com").isEmpty()) {
            User admin = User.builder()
                    .email("admin@example.com")
                    .password(passwordEncoder.encode("Admin@123456"))
                    .fullName("System Administrator")
                    .provider(User.AuthProvider.LOCAL)
                    .role(User.Role.ADMIN)
                    .build();
            userRepository.save(admin);
            System.out.println("First Admin account created: admin@example.com / Admin@123456");
        }
    }
}