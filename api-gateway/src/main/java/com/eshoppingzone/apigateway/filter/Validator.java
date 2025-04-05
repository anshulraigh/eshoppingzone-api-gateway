package com.eshoppingzone.apigateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class Validator {
    public static final List<String> openEndPoints = List.of(
            "/register",
            "/generateToken",
            "/validateToken"
    );
    Predicate<ServerHttpRequest> isSecure = serverHttpRequest ->
            openEndPoints.stream()
                    .noneMatch(uri -> serverHttpRequest.getURI().getPath().contains(uri));
}
