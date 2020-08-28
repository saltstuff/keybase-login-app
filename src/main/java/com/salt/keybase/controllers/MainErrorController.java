package com.salt.keybase.controllers;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class MainErrorController implements ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(MainErrorController.class);
    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // get error status
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        String errorMessage="";


        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            // display specific error page
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                errorMessage="The requested resource cannot be found.";
            } else if (statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                errorMessage="Internal server error.";
            } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                errorMessage="Access to this resource is denied.";
            } else {
                errorMessage="Unexpected error occured.";
            }
        }
        logger.error(errorMessage);
        model.addAttribute("errorMessage", errorMessage);
        // display generic error
        return "errorpage";
    }

}