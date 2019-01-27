package autenticationserver.controller

import java.io.IOException
import java.util

import autenticationserver.configuration.{CustomJdbcUserDetailsManager, CustomUserDetails}
import javax.annotation.Resource
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.support.MessageSourceAccessor
import org.springframework.http.{HttpStatus, ResponseEntity}
import org.springframework.security.core.SpringSecurityMessageSource
import org.springframework.security.core.userdetails.{UserDetails, UserDetailsService}
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore
import org.springframework.security.oauth2.provider.token.{ConsumerTokenServices, TokenStore}
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation._
import autenticationserver.services.{User, UserService}

@Controller
class TokenController(@Resource(name = "tokenServices") tokenServices: ConsumerTokenServices,
                      @Resource(name = "tokenStore") tokenStore: TokenStore,
                      userDetailsService: UserDetailsService,
                      userService: UserService) {

  @Value("${microservices.series.authentication-server.redirecturl}") private[controller] val tokenConfirmationRedirectUrl = null

  protected var messages: MessageSourceAccessor = SpringSecurityMessageSource.getAccessor

  private val log = LoggerFactory.getLogger(classOf[UserService])

  @RequestMapping(method = Array(RequestMethod.POST), value = Array("/oauth/token/revokeById/{tokenId}"))
  @ResponseBody def revokeToken(request: HttpServletRequest, @PathVariable tokenId: String): Unit = {
    tokenServices.revokeToken(tokenId)
  }

  @RequestMapping(method = Array(RequestMethod.GET), value = Array("/tokens"))
  @ResponseBody def getTokens: util.List[String] = {
    val tokenValues: util.List[String] = new util.ArrayList[String]
    val tokens: util.Collection[OAuth2AccessToken] = tokenStore.findTokensByClientId("sampleClientId")
    if (tokens != null) {
      import scala.collection.JavaConversions._
      for (token <- tokens) {
        tokenValues.add(token.getValue)
      }
    }
    tokenValues
  }

  @RequestMapping(method = Array(RequestMethod.POST), value = Array("/tokens/revokeRefreshToken/{tokenId:.*}"))
  @ResponseBody def revokeRefreshToken(@PathVariable tokenId: String): String = {
    if (tokenStore.isInstanceOf[JdbcTokenStore]) tokenStore.asInstanceOf[JdbcTokenStore].removeRefreshToken(tokenId)
    tokenId
  }

  @RequestMapping(method = Array(RequestMethod.POST), value = Array("/user-create")) def postMessage(@RequestBody user: User): ResponseEntity[String] = {
    userService.createUser(user)
    new ResponseEntity[String]("OK", HttpStatus.CREATED)
  }

  @RequestMapping(method = Array(RequestMethod.GET), value = Array("/confirm-token"))
  @ResponseStatus(HttpStatus.OK) def confirmEmailToken(@RequestParam token: String, response: HttpServletResponse): Unit = {
    val customService: CustomJdbcUserDetailsManager = userDetailsService.asInstanceOf[CustomJdbcUserDetailsManager]
    val username: String = customService.getUserNameByToken(token)
    val userDetails: UserDetails = customService.loadUserByUsername(username)
    val userUpdate: UserDetails = new CustomUserDetails(new org.springframework.security.core.userdetails.User(userDetails.getUsername, userDetails.getPassword, true, userDetails.isAccountNonExpired, userDetails.isCredentialsNonExpired, userDetails.isAccountNonLocked, userDetails.getAuthorities), userDetails.asInstanceOf[CustomUserDetails].getExternalid)
    customService.updateUser(userUpdate)
    try
      response.sendRedirect(tokenConfirmationRedirectUrl)
    catch {
      case e: IOException =>
        log.error("Error", e)
    }
  }
}