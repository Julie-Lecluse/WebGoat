package org.owasp.webgoat.container.users;

import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Controller
@AllArgsConstructor
@Slf4j
public class RegistrationController {

  private UserValidator userValidator;
  private UserService userService;

  @GetMapping("/registration")
  public String showForm(UserForm userForm) {
    return "registration";
  }

  private boolean isValidString(String string) {
    // Example: Allow only alphanumeric characters, underscores, and hyphens
    return string.matches("^[a-zA-Z0-9_-]+$");
}

  @PostMapping("/register.mvc")
  public String registration(
      @ModelAttribute("userForm") @Valid UserForm userForm,
      BindingResult bindingResult,
      HttpServletRequest request)
      throws ServletException {
    userValidator.validate(userForm, bindingResult);

    if (bindingResult.hasErrors()) {
      return "registration";
    }
    if (isValidString(userForm.getUsername()) && isValidString(userForm.getPassword())){
      userService.addUser(userForm.getUsername(), userForm.getPassword());
      request.login(userForm.getUsername(), userForm.getPassword());
    }
    return "redirect:/attack";
  }

  @GetMapping("/login-oauth.mvc")
  public String registrationOAUTH(Authentication authentication, HttpServletRequest request)
      throws ServletException {
    log.info("register oauth user in database");
    userService.addUser(authentication.getName(), UUID.randomUUID().toString());
    return "redirect:/welcome.mvc";
  }
}
