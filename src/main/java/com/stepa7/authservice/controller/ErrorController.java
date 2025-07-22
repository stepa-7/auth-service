package com.stepa7.authservice.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            model.addAttribute("status", statusCode);
            switch (statusCode) {
                case 401 -> model.addAttribute("error", "Пользователь не авторизован");
                case 403 -> model.addAttribute("error", "Доступ запрещён");
                case 404 -> model.addAttribute("error", "Страница не найдена");
                default -> model.addAttribute("error", "Неизвестная ошибка");
            }
        }
        return "error";
    }
}
