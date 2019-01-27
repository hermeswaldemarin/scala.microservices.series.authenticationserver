package autenticationserver.services

import java.nio.charset.Charset
import java.security.NoSuchProviderException
import java.util

import autenticationserver.configuration.{CustomJdbcUserDetailsManager, CustomUserDetails}
import javax.mail.internet.MimeMessage
import org.apache.commons.io.IOUtils
import org.json.{JSONException, JSONObject}
import org.slf4j.{Logger, LoggerFactory}
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.support.MessageSourceAccessor
import org.springframework.core.annotation.Order
import org.springframework.core.io.Resource
import org.springframework.http.ResponseEntity
import org.springframework.mail.javamail.{JavaMailSender, MimeMessageHelper, MimeMessagePreparator}
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.SpringSecurityMessageSource
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.{UserDetails, UserDetailsService, UsernameNotFoundException}
import org.springframework.stereotype.Component
import org.springframework.web.client.RestTemplate

import scala.beans.BeanProperty

@Component
@Order(150)
class UserService (userDetailsService: UserDetailsService, restTemplate: RestTemplate, emailSender: JavaMailSender) {
  var log : Logger = LoggerFactory.getLogger(classOf[UserService])

  @Value("classpath:mail-confirmation.html") private val mailConfirmation : Resource = null

  @Value("classpath:logo.jpeg") private val logo : Resource = null

  @Value("${microservices.series.authentication-server.url}") private val urlAutenticationServer = null

  protected var messages: MessageSourceAccessor = SpringSecurityMessageSource.getAccessor

  @throws[NoSuchProviderException]
  def checkExternalProviderCredentials(externalProvider: String, externalAccessToken: String, externalId: String): Unit = {
    if (externalProvider == "facebook") {
      val retorno: ResponseEntity[String] = restTemplate.getForEntity("https://graph.facebook.com/me?access_token=" + externalAccessToken, classOf[String])
      try {
        val `object`: JSONObject = new JSONObject(retorno.getBody)
        if (!(`object`.get("id") == externalId)) throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"))
      } catch {
        case e: JSONException =>
          log.error("Error", e)
      }
    }
    else if (externalProvider == "local") if (externalAccessToken == "") throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"))
    else throw new NoSuchProviderException("Invalid Provider")
  }

  def createUser(user: User): Unit = {
    try {
      val userDetails: UserDetails = userDetailsService.loadUserByUsername(user.getUsername)
      log.info(userDetails.getUsername)
    } catch {
      case e: UsernameNotFoundException =>
        try
          this.checkExternalProviderCredentials(user.getExternalProvider, user.getExternalAccessToken, user.getExternalId)
        catch {
          case e1: NoSuchProviderException =>
            throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"))
        }
        val customService: CustomJdbcUserDetailsManager = userDetailsService.asInstanceOf[CustomJdbcUserDetailsManager]
        val userTemp: CustomUserDetails = new CustomUserDetails(new org.springframework.security.core.userdetails.User(user.getUsername, if (user.getExternalProvider == "local") user.getExternalAccessToken
        else "!?microservices#@internal#2017#", false, true, true, true, util.Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))), user.getExternalId)
        customService.createUser(userTemp)
        val token: String = customService.createMailToken(userTemp)
        val preparator: MimeMessagePreparator = (mimeMessage: MimeMessage) => {
          val helper: MimeMessageHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8")
          helper.setSubject("Welcome to HermesWaldemarin Microservices Series.")
          helper.setFrom("contact@hermeswaldemarin.com.br")
          helper.setTo(user.getUsername)
          val content: String = IOUtils.toString(mailConfirmation.getInputStream, Charset.defaultCharset).replace("{{token}}", token).replace("{{autenticationserver-url}}", urlAutenticationServer)
          // Add an inline resource.
          // use the true flag to indicate you need a multipart message
          helper.setText(content, true)
          helper.addInline("company-logo", logo)
        }
        emailSender.send(preparator)
    }
  }
}

case class User(@BeanProperty username: String,
                @BeanProperty externalId: String,
                @BeanProperty externalProvider: String,
                @BeanProperty externalAccessToken: String)