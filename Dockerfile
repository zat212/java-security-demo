# ==========================================
# Stage 1: Build Stage (Maven + Java 21)
# ==========================================
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder

WORKDIR /app

# Maven dependencies များကို cache ရရှိစေရန် pom.xml နှင့် wrapper များ စကူးပါမည်
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline

# Source code များကို Copy ကူးပြီး JAR file ထုတ်ပါမည်
COPY src ./src
RUN ./mvnw clean package -DskipTests

# ==========================================
# Stage 2: Run Stage (Lightweight JRE 21)
# ==========================================
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Security အတွက် Non-root Spring user ဆောက်ပြီး သုံးပါမည်
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Stage 1 (builder) မှ ထွက်လာသော JAR file ကိုသာ Copy ကူးယူပါမည်
COPY --from=builder /app/target/*.jar app.jar

# Spring Boot App Running Port
EXPOSE 8080

# App ကို စတင် Run မည့် Command
ENTRYPOINT ["java", "-jar", "app.jar"]