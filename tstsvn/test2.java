package com.epam.growthhub.sso.web;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.epam.growthhub.sso.service.SsoService;

/**
 * Servlet implementation class AuthenticationServlet
 */
public class LogoutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final Logger LOG = Logger.getLogger("AuthenticationServlet");
    private SsoService authService;

    /**
     * @throws IOException
     * @see HttpServlet#HttpServlet()
     */
    public LogoutServlet() throws IOException {
	super();
	try {
	    Context context = new InitialContext();
	    authService = (SsoService) context.lookup("osgi:service/"
		    + SsoService.class.getName());
	} catch (NamingException e) {
	    LOG.log(Level.FINER, e.toString());
	}
    }

    public void setAuthenticationService(SsoService authService) {
	this.authService = authService;

    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request,
	    HttpServletResponse response) throws ServletException, IOException {

    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest request,
	    HttpServletResponse response) throws ServletException, IOException {

	String userId = authService.getUserIdBySecuredToken(request.getParameter("securedtoken"));
	
	LOG.info("SSO checking sessionId for user logout");
	if (userId != null) {
	    LOG.info("SSO remove data for this sessionId");
	    authService.removeUserInfo(userId);

	    authService.removeSecuredToken(request.getParameter("securedtoken"));

	    authService.removeTempToken(userId);
	}
	return;
    }

}
