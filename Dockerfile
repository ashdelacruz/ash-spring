#Multi-stage Dockerfile for building an Angular application 
#that runs on an Nginx server 



FROM eclipse-temurin:17-jdk-jammy as build-stage
WORKDIR /opt/ash-backend
COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN ./mvnw dependency:go-offline
COPY ./src ./src
RUN ./mvnw clean install 
 
FROM --platform=linux/arm/v8 eclipse-temurin:17-jre-jammy AS run-stage
#FROM eclipse-temurin:17-jre-jammy AS run-stage
WORKDIR /opt/ash-backend
EXPOSE 80
COPY --from=build-stage /opt/ash-backend/target/*.jar /opt/ash-backend/*.jar
ENTRYPOINT ["java", "-jar", "/opt/ash-backend/*.jar" ]

# FROM maven:3.9.6-eclipse-temurin-17 AS build-stage
# WORKDIR /ash-backend
# COPY .mvn/ .mvn
# COPY mvnw pom.xml ./
# RUN ./mvnw dependency:go-offline

# # COPY src ./src
# # RUN mvn clean install

# CMD mvn spring-boot:run