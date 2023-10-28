package com.example.jsfprojecet.beans;

import com.example.jsfprojecet.model.JwtRequest;
import com.example.jsfprojecet.model.JwtResponse;
import com.example.jsfprojecet.service.JwtAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;


import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;

@ManagedBean(name = "loginBean")
@Controller
@SessionScoped
public class LoginBean implements Serializable {

    private final JwtAuthenticationService jwtAuthenticationService;

    private String userName;
    private String password;

    public LoginBean(JwtAuthenticationService jwtAuthenticationService) {
        this.jwtAuthenticationService = jwtAuthenticationService;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void validateUserLogin() throws Exception {

        System.out.println("Entered Username is= " + userName + ", password is= " + password);

        System.out.println("aurh is = "+ SecurityContextHolder.getContext().getAuthentication().getName());
        JwtRequest request=new JwtRequest(userName,password);
        JwtResponse response=jwtAuthenticationService.createAuthenticationToken(request);
        System.out.println("Token is = "+response.getToken()) ;
        System.out.println("aurh is = "+ SecurityContextHolder.getContext().getAuthentication().getName());

        HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(true);
        session.setAttribute("token",response.getToken());
        ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
        context.redirect(context.getRequestContextPath() + "/home.xhtml" );

    }

    public void userLogout() throws IOException {
        HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
        SecurityContextHolder.clearContext();
        session.invalidate();
        ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
        context.redirect(context.getRequestContextPath() + "/login.xhtml" );
    }

}