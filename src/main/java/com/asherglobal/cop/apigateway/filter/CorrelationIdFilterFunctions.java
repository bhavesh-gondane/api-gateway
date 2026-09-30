package com.asherglobal.cop.apigateway.filter;

import org.slf4j.MDC;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.util.UUID;

public final class CorrelationIdFilterFunctions {

    public static final String CORRELATION_ID_HEADER = "X-Correlation-ID";
    public static final String MDC_KEY = "correlationId";

    private CorrelationIdFilterFunctions() {
    }

    public static HandlerFilterFunction<ServerResponse, ServerResponse> correlationId() {

        return (request, next) -> {

            var ref = new Object() {
                String correlationId =
                        request.headers().firstHeader(CORRELATION_ID_HEADER);
            };

            if (ref.correlationId == null || ref.correlationId.isBlank()) {
                ref.correlationId = UUID.randomUUID().toString();
            }

            MDC.put(MDC_KEY, ref.correlationId);

            try {

                ServerRequest modifiedRequest =
                        ServerRequest.from(request)
                                .headers(headers ->
                                        headers.set(
                                                CORRELATION_ID_HEADER,
                                                ref.correlationId))
                                .build();

                ServerResponse response =
                        next.handle(modifiedRequest);

                response.headers().set(
                        CORRELATION_ID_HEADER,
                        ref.correlationId);

                return response;

            } finally {
                MDC.remove(MDC_KEY);
            }
        };
    }
}