package com.asherglobal.cop.apigateway.filter;

import org.springframework.cloud.gateway.server.mvc.filter.SimpleFilterSupplier;
import org.springframework.stereotype.Component;

@Component
public class CorrelationIdFilterSupplier
        extends SimpleFilterSupplier {

    public CorrelationIdFilterSupplier() {
        super(CorrelationIdFilterFunctions.class);
    }
}